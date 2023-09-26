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

#include <cstring>
#include <functional>
#include "butil/base64.h"
#include "butil/sha1.h"
#include "brpc/log.h"
#include "brpc/details/ws_message.h"

namespace brpc {

const std::string WsMessage::_host_header = "Host";
const std::string WsMessage::_upgrade_header = "Upgrade";
const std::string WsMessage::_upgrade_header_value = "websocket";
const std::string WsMessage::_connection_header = "Connection";
const std::string WsMessage::_connection_header_value = "Upgrade";
const std::string WsMessage::_ws_key_header = "Sec-WebSocket-Key";
const std::string WsMessage::_ws_version_header = "Sec-WebSocket-Version";
const std::string WsMessage::_ws_version_header_value = "13";
const std::string WsMessage::_ws_protocol_header = "Sec-WebSocket-Protocol";
const std::string WsMessage::_ws_extend_header = "Sec-WebSocket-Extensions";
const std::string WsMessage::_ws_magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

WsMessage::WsMessage() {
    ws_parser_init(&_hs_parser, &_data_parser);
    _hs_parser.ws_message_ptr = this;
    _data_parser.ws_message_ptr = this;
    std::memset(_cur_header_key, 0, 4096);
    std::memset(_cur_header_value, 0, 4096);
}

ssize_t WsMessage::ParseFromIOBuf(const butil::IOBuf &buf) {
    if (Completed()) {
        if (buf.empty()) {
            return 0;
        }

        return -1;
    }

    ssize_t nprocessed = 0;
    for (size_t i = 0; i < buf.backing_block_num(); ++i) {
        butil::StringPiece blk = buf.backing_block(i);
        if (blk.empty()) {
            continue;
        }

        nprocessed += ws_parser_execute(
            &_hs_parser, &_data_parser, blk.data(), blk.size());
        if (_hs_parser.ws_errno != WsErrno::VALID ||
            _data_parser.ws_errno != static_cast<uint16_t>(WsErrno::VALID)) {
            RPC_VLOG << "Fail to parse ws message, buf=`"
                << butil::ToPrintable(buf)
                << ", handshake errno " << static_cast<uint16_t>(_hs_parser.ws_errno)
                << ", data errno " << static_cast<uint16_t>(_data_parser.ws_errno);
            return -1;
        }
        if (Completed()) {
            break;
        }
    }

    _parsed_length += nprocessed;
    return nprocessed;
}

ssize_t WsMessage::ParseFromArray(const char *data, const size_t length) {
    if (Completed()) {
        if (length == 0) {
            return 0;
        }
        LOG(ERROR) << "Append data(len=" << length
                   << ") to already-completed message";
        return -1;
    }

    const size_t nprocessed =
        ws_parser_execute(&_hs_parser, &_data_parser, data, length);
    if (_hs_parser.ws_errno != WsErrno::VALID ||
        _data_parser.ws_errno != static_cast<uint16_t>(WsErrno::VALID)) {
        RPC_VLOG << "Fail to parse ws message, buf=`"
            << butil::StringPiece(data, length) << '\''
            << ", handshake errno " << static_cast<uint16_t>(_hs_parser.ws_errno)
            << ", data errno " << static_cast<uint16_t>(_data_parser.ws_errno);
        return -1;
    }

    _parsed_length += nprocessed;
    return nprocessed;
}

void WsMessage::on_set_pkgtype(WsPkgType pkg_type) {
    _pkg_type = pkg_type;
}

bool WsMessage::on_opcode(char opcode) {
    switch (static_cast<WsOpcode>(opcode))
    {
    case WsOpcode::CONTINUATION_FRAME:
    case WsOpcode::TEXT_FRAME:
    case WsOpcode::BINARY_FRAME:
    case WsOpcode::CLOSE_FRAME:
    case WsOpcode::PING_FRAME:
    case WsOpcode::PONG_FRAME:
        return true;
    
    default:
        break;
    }

    return false;
}

void WsMessage::on_set_mask_key(char ch) {
    if (_mask_key.empty()) {
        _mask_key.reserve(4);
    }

    _mask_key.push_back(ch);
}

ssize_t WsMessage::on_body(
    ws_data_parser* data_parser, const char* data, const size_t len) {
    if (Completed()) {
        return 0;
    }

    size_t read_len =
        std::min(data_parser->payload_length - data_parser->readed_length, len);
    if (0 == data_parser->mask) {
        _body.append(data, read_len);
    } else {
        // TODO modify in-place?
        size_t idx = data_parser->readed_length;
        std::string res;
        res.reserve(read_len);
        for (size_t i = 0; i < read_len; ++i) {
            res += (data[i] ^ _mask_key[idx++ % 4]);
        }

        _body.append(res.data(), read_len);
    }

    data_parser->readed_length += read_len;
    return read_len;
}

bool WsMessage::on_header_end() {
    bool ret = true;
    if (_cur_key_pos == std::strlen(_host_header.data()) &&
        !std::memcmp(_cur_header_key, _host_header.data(), _cur_key_pos)) {
        if (HostCheck()) {
            _header_checker |= 0b00000001;
        } else {
            ret = false;
        }
    } else if (_cur_key_pos == std::strlen(_upgrade_header.data()) &&
        !std::memcmp(_cur_header_key, _upgrade_header.data(), _cur_key_pos)) {
        if (UpgradeCheck()) {
            _header_checker |= 0b00000010;
        } else {
            ret = false;
        }
    } else if (_cur_key_pos == std::strlen(_connection_header.data()) &&
        !std::memcmp(_cur_header_key, _connection_header.data(), _cur_key_pos)) {
        if (ConnectionCheck()) {
            _header_checker |= 0b00000100;
        } else {
            ret = false;
        }
    } else if (_cur_key_pos == std::strlen(_ws_key_header.data()) &&
        !std::memcmp(_cur_header_key, _ws_key_header.data(), _cur_key_pos)) {
        if (WsKeyCheck()) {
            _ws_key.assign(_cur_header_value, _cur_val_pos);
            _header_checker |= 0b00001000;
        } else {
            ret = false;
        }
    } else if (_cur_key_pos == std::strlen(_ws_version_header.data()) &&
        !std::memcmp(_cur_header_key, _ws_version_header.data(), _cur_key_pos)) {
        if (WsVersionCheck()) {
            _header_checker |= 0b00010000;
        } else {
            ret = false;
        }
    } else if (_cur_key_pos == std::strlen(_ws_protocol_header.data()) &&
        !std::memcmp(_cur_header_key, _ws_protocol_header.data(), _cur_key_pos) &&
        _cur_val_pos > 0) {
        _ws_protocol.assign(_cur_header_value, _cur_val_pos);
    } else if (_cur_key_pos == std::strlen(_ws_extend_header.data()) &&
        !std::memcmp(_cur_header_key, _ws_extend_header.data(), _cur_key_pos) &&
        _cur_val_pos > 0) {
        _ws_extend.assign(_cur_header_value, _cur_val_pos);
    }

    std::memset(_cur_header_key, 0, _cur_key_pos);
    std::memset(_cur_header_value, 0, _cur_val_pos);
    _cur_key_pos = _cur_val_pos = 0;
    return ret;
}

void WsMessage::MakeHandshakeResp(butil::IOBuf* response) {
    std::string user_key =
        butil::string_printf("%s%s", _ws_key.data(), _ws_magic.data());
    std::string resp_key = butil::SHA1HashString(user_key);
    std::string encoded_resp_key = "";
    butil::Base64Encode(resp_key, &encoded_resp_key);

    butil::IOBufBuilder os;
    os << "HTTP/1.1 101 Switching Protocols" 
        << "\r\n"
        << "Upgrade: websocket"
        << "\r\n"
        << "Connection: Upgrade"
        << "\r\n"
        << "Sec-WebSocket-Accept:"
        << encoded_resp_key
        << "\r\n\r\n";
    os.move_to(*response);
}

}
