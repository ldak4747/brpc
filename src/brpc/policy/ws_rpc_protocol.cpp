// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.


#include <google/protobuf/descriptor.h>             // MethodDescriptor
#include <google/protobuf/text_format.h>
#include <gflags/gflags.h>
#include <json2pb/pb_to_json.h>                    // ProtoMessageToJson
#include <json2pb/json_to_pb.h>                    // JsonToProtoMessage
#include <string>

#include "brpc/policy/ws_rpc_protocol.h"
#include "butil/unique_ptr.h"                       // std::unique_ptr
#include "butil/string_splitter.h"                  // StringMultiSplitter
#include "butil/string_printf.h"
#include "butil/time.h"
#include "butil/sys_byteorder.h"
#include "brpc/compress.h"
#include "brpc/errno.pb.h"                          // ENOSERVICE, ENOMETHOD
#include "brpc/controller.h"                        // Controller
#include "brpc/server.h"                            // Server
#include "brpc/details/server_private_accessor.h"
#include "brpc/socket.h"                            // Socket
#include "brpc/rpc_dump.h"                          // SampledRequest
#include "brpc/http_status_code.h"                  // HTTP_STATUS_*
#include "brpc/details/controller_private_accessor.h"
#include "brpc/builtin/index_service.h"             // IndexService
#include "brpc/policy/gzip_compress.h"
#include "brpc/policy/websocket.pb.h"
#include "brpc/details/usercode_backup_pool.h"

namespace brpc {
namespace policy {

template<class T>
void PackPayloadLength(butil::IOBuf* buf, T* payload_length) {
    uint8_t* ptr = reinterpret_cast<uint8_t*>(payload_length);
    for (int64_t pos = sizeof(T) - 1; pos >= 0; --pos) {
        buf->append(ptr + pos, 1);
    }
}

// TODO support mask_key
// TODO need check?
bool PackWsMsgToIOBuf(
    butil::IOBuf* send_buf, int8_t fin, int8_t opcode, int8_t mask,
    size_t message_length, const std::string& mask_key,
    const char* payload) {
    if (!send_buf) {
        return false;
    }

    char fin_opcode = 0;
    fin_opcode |= (fin << 7);
    fin_opcode |= opcode;
    send_buf->append(&fin_opcode, sizeof(fin_opcode));

    // mask, payload_length, in second bytes
    char mask_payload = 0;
    if (message_length < 126) {
        mask_payload = static_cast<char>(message_length);
        send_buf->append(&mask_payload, sizeof(mask_payload));
    } else if (message_length < 65536) {
        mask_payload = 126;
        send_buf->append(&mask_payload, sizeof(mask_payload));
        uint16_t payload_length = static_cast<uint16_t>(message_length);
        PackPayloadLength(send_buf, &payload_length);
    } else {
        mask_payload = 127;
        send_buf->append(&mask_payload, sizeof(mask_payload));
        PackPayloadLength(send_buf, &message_length);
    }

    // data
    send_buf->append(payload, message_length);
    return true;
}

void MakeWsProtoRequest(WsContext* msg, WebSocketRequest* req) {
    auto* header = req->mutable_header();
    header->set_message_length(msg->PayloadLength());
    header->set_fin(msg->Fin());
    header->set_opcode(static_cast<WebSocketOpcode>(msg->Opcode()));
    const auto& mask_key = msg->MaskKey();
    if (!mask_key.empty()) {
        std::string str_mask_key;
        str_mask_key.assign(mask_key.data(), mask_key.size());
        header->mutable_mask_key()->swap(str_mask_key);
    }

    std::string body = msg->body().to_string();
    req->mutable_message()->swap(body);
}

// Defined in baidu_rpc_protocol.cpp
void EndRunningCallMethodInPool(
    ::google::protobuf::Service* service,
    const ::google::protobuf::MethodDescriptor* method,
    ::google::protobuf::RpcController* controller,
    const ::google::protobuf::Message* request,
    ::google::protobuf::Message* response,
    ::google::protobuf::Closure* done);

void ProcessWsRequest(InputMessageBase* msg) {
    #ifdef WS_PROFILE
    const int64_t start_parse_us = butil::cpuwide_time_us();
    #endif
    DestroyingPtr<WsContext> imsg_guard(dynamic_cast<WsContext*>(msg));
    SocketUniquePtr socket_guard(imsg_guard->ReleaseSocket());
    Socket* socket = socket_guard.get();
    const Server* server = static_cast<const Server*>(msg->arg());
    // running check
    if (!server->IsRunning()) {
        return;
    }

    // overcrowded check
    if (socket->is_overcrowded()) {
        return;
    }

    // handshake response
    if (imsg_guard->PkgType() == WsPkgType::HANDSHAKE) {
        butil::IOBuf resp;
        imsg_guard->MakeHandshakeResp(&resp);
        Socket::WriteOptions wopt;
        wopt.ignore_eovercrowded = true;
        socket->Write(&resp, &wopt);
        return;
    }

    // close frame
    if (dynamic_cast<WsContext*>(msg)->Opcode() ==
        static_cast<int32_t>(WsOpcode::CLOSE_FRAME)) {
        socket->SetFailed();
        return;
    }

    // relate services
    const google::protobuf::ServiceDescriptor* srv_des =
        WebSocketService::descriptor();
    const Server::MethodProperty *mp =
            ServerPrivateAccessor(server)
            .FindMethodPropertyByFullName(srv_des->method(0)->full_name());
    if (!mp || mp->service->GetDescriptor() == BadMethodService::descriptor()) {
        LOG(ERROR) << "Fail to find default_method";
        return;
    }

    // method status check
    MethodStatus* method_status = mp->status;
    if (method_status) {
        int32_t rejected_cc = 0;
        if (!method_status->OnRequested(&rejected_cc)) {
            return;
        }
    }

    // controller alloc and setup
    Controller* cntl = new (std::nothrow) Controller;
    if (!cntl) {
        LOG(FATAL) << "Fail to new Controller";
        return;
    }
    WebSocketSender resp_sender;
    ControllerPrivateAccessor accessor(cntl);
    butil::EndPoint user_addr = socket->remote_side();
    accessor.set_server(server)
        .set_security_mode(server->options().security_mode())
        .set_peer_id(socket->id())
        .set_remote_side(socket->remote_side())
        .set_local_side(socket->local_side())
        .set_auth_context(socket->auth_context())
        .set_request_protocol(PROTOCOL_WEBSOCKET)
        .set_begin_time_us(msg->received_us())
        .move_in_server_receiving_sock(socket_guard);
    accessor.set_method(mp->method);

    // concurrency check
    if (!ServerPrivateAccessor(server).AddConcurrency(cntl)) {
        return;
    }

    // protobuf request and done wrapper
    google::protobuf::Message* req =
        mp->service->GetRequestPrototype(mp->method).New();
    resp_sender._req.reset(req);
    MakeWsProtoRequest(
        dynamic_cast<WsContext*>(msg), dynamic_cast<WebSocketRequest*>(req));
    google::protobuf::Message* res =
        mp->service->GetResponsePrototype(mp->method).New();
    resp_sender._res.reset(res);
    google::protobuf::Closure* done = new WebSocketSenderAsDone(resp_sender);

    // user code process
    if (BeginRunningUserCode()) {
        mp->service->CallMethod(mp->method, cntl, req, res, done);
        EndRunningUserCodeInPlace();
    } else {
        EndRunningCallMethodInPool(
            mp->service, mp->method, cntl, req, res, done);
    }
}

ParseResult ParseWsMessage(butil::IOBuf *source, Socket *socket,
                           bool read_eof, const void* arg) {
    WsContext* ws_imsg = dynamic_cast<WsContext*>(socket->parsing_context());
    if (!ws_imsg) {
        if (read_eof || source->empty()) {
            return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
        }

        ws_imsg = new (std::nothrow) WsContext();
        if (!ws_imsg) {
            LOG(FATAL) << "Fail to new WsContext";
            return MakeParseError(PARSE_ERROR_NO_RESOURCE);
        }

        socket->reset_parsing_context(ws_imsg);
    }

    ssize_t rc = 0;
    if (read_eof) {
        rc = ws_imsg->ParseFromArray(0, 0);
    } else {
        rc = ws_imsg->ParseFromIOBuf(*source);
    }

    if (rc < 0) {
        return MakeParseError(PARSE_ERROR_TRY_OTHERS);
    }

    source->pop_front(rc);    
    if (!rc || !ws_imsg->Completed()) {
        return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    }

    if (ws_imsg->Completed()) {
        CHECK_EQ(ws_imsg, socket->release_parsing_context());
        return MakeMessage(ws_imsg);
    }
    
    return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
}

bool VerifyWsRequest(const InputMessageBase* msg) {
    // Server* server = (Server*)msg->arg();
    // Socket* socket = msg->socket();
    
    // WsContext* ws_imsg = dynamic_cast<WsContext*>(msg);
    // (void)ws_imsg;
    // const Authenticator* auth = server->options().auth;
    // if (!auth) {
    //     return true;
    // }

    // TODO support Authorization
    return true;
}

} // namespace policy
} // namespace brpc
