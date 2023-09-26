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


#ifndef BRPC_POLICY_WS_RPC_PROTOCOL_H
#define BRPC_POLICY_WS_RPC_PROTOCOL_H

#include "brpc/server.h"
#include "brpc/details/ws_message.h"        // WsMessage
#include "brpc/input_messenger.h"           // InputMessenger
#include "brpc/protocol.h"                  // LogErrorTextAndDelete

namespace brpc {
namespace policy {

struct WebSocketSender {
    WebSocketSender() = default;
    WebSocketSender(WebSocketSender&& other) {
        _req = std::move(other._req);
        _res = std::move(other._res);
    }
    ~WebSocketSender() = default;
    std::unique_ptr<google::protobuf::Message> _req;
    std::unique_ptr<google::protobuf::Message> _res;
};

bool PackWsMsgToIOBuf(
    butil::IOBuf* send_buf, int8_t fin, int8_t opcode, int8_t mask,
    size_t message_length, const std::string& mask_key,
    const char* payload);

struct WsContext : public ReadableProgressiveAttachment
                   , public InputMessageBase
                   , public WsMessage {
    WsContext() : InputMessageBase(), WsMessage() {}
    // @InputMessageBase
    virtual void DestroyImpl() override {
        delete this;
    }
    // @ReadableProgressiveAttachment
    virtual void ReadProgressiveAttachmentBy(ProgressiveReader* r) override {
        return;
    }
};

class WebSocketSenderAsDone : public google::protobuf::Closure {
public:
    WebSocketSenderAsDone(WebSocketSender& sender) : _sender(std::move(sender)) {}
    virtual ~WebSocketSenderAsDone() {}
    virtual void Run() override { delete this; }

private:
    WebSocketSender _sender;
};

ParseResult ParseWsMessage(butil::IOBuf *source, Socket *socket,
                           bool read_eof, const void *arg);
void ProcessWsRequest(InputMessageBase *msg);
bool VerifyWsRequest(const InputMessageBase* msg);

} // namespace policy
} // namespace brpc

#endif // BRPC_POLICY_WS_RPC_PROTOCOL_H
