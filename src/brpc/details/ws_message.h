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


#ifndef BRPC_WS_MESSAGE_H
#define BRPC_WS_MESSAGE_H

#include <string>                       // std::string
#include "butil/macros.h"
#include "butil/iobuf.h"                // butil::IOBuf
#include "butil/scoped_lock.h"          // butil::unique_lock
#include "butil/endpoint.h"
#include "brpc/details/ws_parser.h"     // ws_parser
#include "brpc/http_header.h"           // HttpHeader
#include "brpc/progressive_reader.h"    // ProgressiveReader

namespace brpc {

class WsMessage {
public:
    WsMessage();
    ~WsMessage() = default;

    const butil::IOBuf &body() const { return _body; }

    // Parse from array, length=0 is treated as EOF.
    // Returns bytes parsed, -1 on failure.
    ssize_t ParseFromArray(const char *data, const size_t length);

    // Parse from butil::IOBuf.
    // Emtpy `buf' is sliently ignored, which is different from ParseFromArray.
    // Returns bytes parsed, -1 on failure.
    ssize_t ParseFromIOBuf(const butil::IOBuf &buf);

    bool Completed() const { 
        return (_pkg_type == WsPkgType::DATA && 
            _data_parser.ws_errno == static_cast<uint16_t>(WsErrno::VALID) &&
            _data_parser.payload_length == _data_parser.readed_length) ||
            (_pkg_type == WsPkgType::HANDSHAKE &&
            (_header_checker & 0b00011111) == 0b00011111);
    }
    WsPkgType PkgType() const {
        return _pkg_type;
    }
    void on_set_pkgtype(WsPkgType pkg_type);
    
    // ws data callbacks
    bool on_opcode(char opcode);
    void on_set_mask_key(char ch);
    ssize_t on_body(
        ws_data_parser* data_parser, const char* data, const size_t len);
    int32_t Fin() const {
        return _data_parser.fin;
    }
    int32_t Opcode() const {
        return _data_parser.opcode;
    }
    int64_t PayloadLength() const {
        return _data_parser.payload_length;
    }
    const std::vector<char>& MaskKey() const {
        return _mask_key;
    }

    // ws handshake callbacks
    bool on_append_header_key(char ch) {
        if (BAIDU_UNLIKELY(_cur_key_pos == 4096)) {
            return false;
        }
        _cur_header_key[_cur_key_pos++] = ch;
        return true;
    }
    bool on_append_header_value(char ch) {
        if (BAIDU_UNLIKELY(_cur_val_pos == 4096)) {
            return false;
        }
        _cur_header_value[_cur_val_pos++] = ch;
        return true;
    }
    bool on_header_end();

    // notify client handshake-success
    void MakeHandshakeResp(butil::IOBuf* response);

    // ws handshake header check
    static const std::string _host_header;
    static const std::string _upgrade_header;
    static const std::string _upgrade_header_value;
    static const std::string _connection_header;
    static const std::string _connection_header_value;
    static const std::string _ws_key_header;
    static const std::string _ws_version_header;
    static const std::string _ws_version_header_value;
    static const std::string _ws_protocol_header;
    static const std::string _ws_extend_header;
    static const std::string _ws_magic;

private:
    DISALLOW_COPY_AND_ASSIGN(WsMessage);
    // ws handshake header check
    bool HostCheck() {
        return _cur_val_pos > 0;
    }
    bool UpgradeCheck() {
        return _cur_val_pos == std::strlen(_upgrade_header_value.data()) &&
            !std::memcmp(_cur_header_value, _upgrade_header_value.data(), _cur_val_pos);
    }
    bool ConnectionCheck() {
        return _cur_val_pos == std::strlen(_connection_header_value.data()) &&
            !std::memcmp(_cur_header_value, _connection_header_value.data(), _cur_val_pos);
    }
    bool WsKeyCheck() {
        return _cur_val_pos > 0;
    }
    bool WsVersionCheck() {
        return _cur_val_pos == std::strlen(_ws_version_header_value.data()) &&
            !std::memcmp(_cur_header_value, _ws_version_header_value.data(), _cur_val_pos);
    }

    // ws message type
    WsPkgType _pkg_type = WsPkgType::UNKNOWN;

    // ws handshake
    char _header_checker = 0;    // 0~4 bits is: Host,Upgrade,Connection,Sec-WebSocket-Key,Sec-WebSocket-Version, 5~7 bits reserved
    size_t _cur_key_pos = 0;
    size_t _cur_val_pos = 0;
    // TODO optimize
    char _cur_header_key[4096];
    char _cur_header_value[4096];
    std::string _ws_key;
    std::string _ws_protocol;
    std::string _ws_extend;

    // ws data
    butil::IOBuf _body;
    std::vector<char> _mask_key;

    // ws parse
    ws_hs_parser _hs_parser;
    ws_data_parser _data_parser;
    size_t _parsed_length = 0;
};

} // namespace brpc

#endif  // BRPC_WS_MESSAGE_H
