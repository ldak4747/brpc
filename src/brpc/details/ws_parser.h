/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */


#ifndef BRPC_WS_PARSER_H
#define BRPC_WS_PARSER_H

#include <sys/types.h>
#if defined(_WIN32) && !defined(__MINGW32__) && (!defined(_MSC_VER) || _MSC_VER<1600)
#include <BaseTsd.h>
#include <stddef.h>
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

namespace brpc {

class WsMessage;
enum class WsPkgType {
    UNKNOWN = 0,
    HANDSHAKE,
    DATA
};

enum class WsOpcode {
    CONTINUATION_FRAME = 0,
    TEXT_FRAME = 1,
    BINARY_FRAME = 2,
    CLOSE_FRAME = 8,
    PING_FRAME = 9,
    PONG_FRAME = 10
};

enum class WsErrno {
    VALID = 0,
    // handshake
    INVALID_METHOD_FORMAT,
    INVALID_LINEBREAK,
    INVALID_HTTP_VERSION,
    INVALID_HTTP_HEADER,
    // data
    INVALID_UNKNOWN_OPCODE,
    INVALID_PAYLOAD_ZERO
};

enum class WsHandShakeState {
    ws_handshake_method_check = 0,
    ws_handshake_method,
    ws_handshake_http_major_version,
    ws_handshake_http_version_dot,
    ws_handshake_http_minor_version,
    ws_handshake_segment_finish1,
    ws_handshake_segment_finish2,
    ws_handshake_header_key,
    ws_handshake_header_value
};

enum class WsDataState {
    ws_data_start = 0,
    ws_data_fin_done,
    ws_data_payload_0,
    ws_data_payload_1,
    ws_data_payload_2,
    ws_data_payload_3,
    ws_data_payload_4,
    ws_data_payload_5,
    ws_data_payload_6,
    ws_data_payload_7,
    ws_mask_key_1,
    ws_mask_key_2,
    ws_mask_key_3,
    ws_mask_key_4,
    ws_data
};

struct ws_hs_parser {
    WsHandShakeState state;
    uint16_t index;
    uint8_t http_major;
    uint8_t http_minor;
    WsErrno ws_errno;
    WsMessage* ws_message_ptr;
};

struct ws_data_parser {
    uint16_t fin          :1;
    uint16_t opcode       :4;
    uint16_t mask         :1;
    uint16_t payload_type :2;     // 0: <126, 1: ==126, 2: ==127
    uint16_t state        :4;
    uint16_t ws_errno     :4;
    size_t payload_length;
    size_t readed_length;
    WsMessage* ws_message_ptr;
};

void ws_parser_init(ws_hs_parser *hs_parser, ws_data_parser* data_parser);
inline void ws_set_state(ws_hs_parser* hs_parser, WsHandShakeState state) {
    hs_parser->state = state;
}
inline void ws_set_state(ws_data_parser* data_parser, WsDataState state) {
    data_parser->state = static_cast<char>(state);
}

ssize_t ws_parser_execute(ws_hs_parser* parser,
                          ws_data_parser* data_parser,
                          const char *data,
                          size_t len);

ssize_t ws_handahake_parser_execute(ws_hs_parser *parser,
                                    const char *data,
                                    size_t len);

ssize_t ws_data_parser_execute(ws_data_parser* data_parser,
                               const char* data,
                               size_t len);

}

#endif // BRPC_WS_PARSER_H
