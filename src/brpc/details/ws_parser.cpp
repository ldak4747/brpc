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


#include "brpc/details/ws_parser.h"
#include "brpc/details/ws_message.h"
#include <assert.h>
#include <stddef.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <cstring>

namespace brpc {

const char* g_ws_method_field = "GET / HTTP/";

#define CR                  '\r'
#define LF                  '\n'
#define LOWER(c)            (unsigned char)(c | 0x20)
#define IS_ALPHA(c)         (LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_NUM(c)           ((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_NUM(c))

void ws_parser_init(ws_hs_parser *hs_parser, ws_data_parser* data_parser) {
    std::memset(hs_parser, 0, sizeof(ws_hs_parser));
    std::memset(data_parser, 0, sizeof(ws_data_parser));
}

ssize_t ws_parser_execute(ws_hs_parser* hs_parser,
                          ws_data_parser* data_parser,
                          const char *data,
                          size_t len) {
    if (0 == len) {
        return 0;
    }

    if (data_parser->state) {
        return ws_data_parser_execute(data_parser, data, len);
    }

    if (*data == 'G') {
        return ws_handahake_parser_execute(hs_parser, data, len);
    }

    switch (*reinterpret_cast<const u_char*>(data))
    {
    case 0b00000000:
    case 0b00000001:
    case 0b00000010:
    case 0b00001000:
    case 0b00001001:
    case 0b00001010:
    case 0b10000000:
    case 0b10000001:
    case 0b10000010:
    case 0b10001000:
    case 0b10001001:
    case 0b10001010:
       return ws_data_parser_execute(data_parser, data, len);
    default:
        break;
    }

    return -1;
}

ssize_t ws_data_parser_execute(ws_data_parser* data_parser,
                               const char* data,
                               size_t len) {
    size_t pos = 0;
    WsMessage* ws_message_handle = data_parser->ws_message_ptr;
    for (; pos < len; ++pos) {
        switch (data_parser->state)
        {
        case static_cast<uint16_t>(WsDataState::ws_data_start):
        {
            data_parser->fin = data[pos] >> 7;
            data_parser->opcode = data[pos] & 0x0F;
            if (!ws_message_handle->on_opcode(data[pos] & 0x0F)) {
                data_parser->ws_errno =
                    static_cast<uint16_t>(WsErrno::INVALID_UNKNOWN_OPCODE);
                return pos;
            }
            ws_set_state(data_parser, WsDataState::ws_data_fin_done);
            break;
        }
        
        case static_cast<uint16_t>(WsDataState::ws_data_fin_done):
        {
            data_parser->mask = data[pos] >> 7;
            char payload_type = data[pos] & 0x7F;
            if (126 > payload_type) {
                data_parser->payload_length = payload_type;
                if (0 == data_parser->payload_length) {
                    data_parser->ws_errno =
                        static_cast<uint16_t>(WsErrno::INVALID_PAYLOAD_ZERO);
                    return pos;
                }
                ws_set_state(data_parser, WsDataState::ws_mask_key_1);
            } else {
                if (126 == payload_type) {
                    data_parser->payload_type = 0x1;
                } else {
                    data_parser->payload_type = 0x2;
                }
                ws_set_state(data_parser, WsDataState::ws_data_payload_0);
            }
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_data_payload_0):
        {
            size_t tmp_data = static_cast<u_char>(data[pos]);
            if (data_parser->payload_type == 0x1) {
                data_parser->payload_length = (tmp_data << 8);
            } else {
                data_parser->payload_length = (tmp_data << 56);
            }
            ws_set_state(data_parser, WsDataState::ws_data_payload_1);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_data_payload_1):
        {
            size_t tmp_data = static_cast<u_char>(data[pos]);
            if (data_parser->payload_type == 0x1) {
                data_parser->payload_length += tmp_data;
                if (0 == data_parser->payload_length) {
                    data_parser->ws_errno =
                        static_cast<uint16_t>(WsErrno::INVALID_PAYLOAD_ZERO);
                    return pos;
                }
                ws_set_state(data_parser, WsDataState::ws_mask_key_1);
            } else {
                data_parser->payload_length += (tmp_data << 48);
                ws_set_state(data_parser, WsDataState::ws_data_payload_2);
            }
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_data_payload_2):
        {
            size_t tmp_data = static_cast<u_char>(data[pos]);
            data_parser->payload_length += (tmp_data << 40);
            ws_set_state(data_parser, WsDataState::ws_data_payload_3);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_data_payload_3):
        {
            size_t tmp_data = static_cast<u_char>(data[pos]);
            data_parser->payload_length += (tmp_data << 32);
            ws_set_state(data_parser, WsDataState::ws_data_payload_4);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_data_payload_4):
        {
            size_t tmp_data = static_cast<u_char>(data[pos]);
            data_parser->payload_length += (tmp_data << 24);
            ws_set_state(data_parser, WsDataState::ws_data_payload_5);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_data_payload_5):
        {
            size_t tmp_data = static_cast<u_char>(data[pos]);
            data_parser->payload_length += (tmp_data << 16);
            ws_set_state(data_parser, WsDataState::ws_data_payload_6);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_data_payload_6):
        {
            size_t tmp_data = static_cast<u_char>(data[pos]);
            data_parser->payload_length += (tmp_data << 8);
            ws_set_state(data_parser, WsDataState::ws_data_payload_7);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_data_payload_7):
        {
            size_t tmp_data = static_cast<u_char>(data[pos]);
            data_parser->payload_length += tmp_data;
            if (0 == data_parser->payload_length) {
                data_parser->ws_errno =
                        static_cast<uint16_t>(WsErrno::INVALID_PAYLOAD_ZERO);
                return pos;
            }
            ws_set_state(data_parser, WsDataState::ws_mask_key_1);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_mask_key_1):
        {
            if (data_parser->mask == 0) {
                ws_set_state(data_parser, WsDataState::ws_data);
                break;
            }

            ws_message_handle->on_set_mask_key(data[pos]);
            ws_set_state(data_parser, WsDataState::ws_mask_key_2);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_mask_key_2):
        {
            ws_message_handle->on_set_mask_key(data[pos]);
            ws_set_state(data_parser, WsDataState::ws_mask_key_3);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_mask_key_3):
        {
            ws_message_handle->on_set_mask_key(data[pos]);
            ws_set_state(data_parser, WsDataState::ws_mask_key_4);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_mask_key_4):
        {
            ws_message_handle->on_set_mask_key(data[pos]);
            ws_set_state(data_parser, WsDataState::ws_data);
            break;
        }

        case static_cast<uint16_t>(WsDataState::ws_data):
        {
            ws_message_handle->on_set_pkgtype(WsPkgType::DATA);
            return pos + ws_message_handle->on_body(data_parser, data + pos, len - pos);
        }

        default:
            break;
        }
    }

    return pos;
}

ssize_t ws_handahake_parser_execute(ws_hs_parser* hs_parser,
                                    const char* data,
                                    size_t len) {
    char ch = 0;
    size_t pos = 0;
    WsMessage* ws_message_handle = hs_parser->ws_message_ptr;
    for (; pos < len; ++pos) {
        ch = data[pos];

        switch (hs_parser->state) {
        case WsHandShakeState::ws_handshake_method_check:
        {
            // ignore \r,\n,blankspaces
            if (ch == CR || ch == LF || ch == ' ')
                break;

            if (ch != g_ws_method_field[0]) {
                hs_parser->ws_errno = WsErrno::INVALID_METHOD_FORMAT;
                return pos;
            }

            ws_set_state(hs_parser, WsHandShakeState::ws_handshake_method);
            ++hs_parser->index;
            break;
        }

        case WsHandShakeState::ws_handshake_method:
        {
            if (g_ws_method_field[hs_parser->index] != ch) {
                hs_parser->ws_errno = WsErrno::INVALID_METHOD_FORMAT;
                return pos;
            }

            ++hs_parser->index;
            if (hs_parser->index == std::strlen(g_ws_method_field)) {
                hs_parser->index = 0;
                ws_set_state(hs_parser, WsHandShakeState::ws_handshake_http_major_version);
            }
            break;
        }
        
        case WsHandShakeState::ws_handshake_http_major_version:
        {
            hs_parser->http_major = static_cast<uint8_t>(ch - 48);
            if (hs_parser->http_major != 1) {
                hs_parser->ws_errno = WsErrno::INVALID_HTTP_VERSION;
                return pos;
            }
            ws_set_state(hs_parser, WsHandShakeState::ws_handshake_http_version_dot);
            break;
        }
        
        case WsHandShakeState::ws_handshake_http_version_dot:
        {
            if (ch != '.') {
                hs_parser->ws_errno = WsErrno::INVALID_METHOD_FORMAT;
                return pos;
            }

            ws_set_state(hs_parser, WsHandShakeState::ws_handshake_http_minor_version);
            break;
        }
        
        case WsHandShakeState::ws_handshake_http_minor_version:
        {
            hs_parser->http_minor = static_cast<uint8_t>(ch - 48);
            if (hs_parser->http_major != 1) {
                hs_parser->ws_errno = WsErrno::INVALID_HTTP_VERSION;
                return pos;
            }
            hs_parser->state = WsHandShakeState::ws_handshake_segment_finish1;
            ws_message_handle->on_set_pkgtype(WsPkgType::HANDSHAKE);
            break;
        }

        case WsHandShakeState::ws_handshake_segment_finish1:
        {
            if (ch != CR) {
                hs_parser->ws_errno = WsErrno::INVALID_LINEBREAK;
                return pos;
            }

            ws_set_state(hs_parser, WsHandShakeState::ws_handshake_segment_finish2);
            break;
        }
        
        case WsHandShakeState::ws_handshake_segment_finish2:
        {
            if (ch != LF) {
                hs_parser->ws_errno = WsErrno::INVALID_LINEBREAK;
                return pos;
            }
            ws_set_state(hs_parser, WsHandShakeState::ws_handshake_header_key);
            break;
        }

        case WsHandShakeState::ws_handshake_header_key:
        {
            if (ch == ':') {
                ws_set_state(hs_parser, WsHandShakeState::ws_handshake_header_value);
            } else {
                ws_message_handle->on_append_header_key(ch);
            }
            break;
        }

        case WsHandShakeState::ws_handshake_header_value:
        {
            if (ch == ' ') {
                break;
            }

            if (ch == CR) {
                if (!ws_message_handle->on_header_end()) {
                    hs_parser->ws_errno = WsErrno::INVALID_HTTP_HEADER;
                    return pos;
                }
                ws_set_state(hs_parser, WsHandShakeState::ws_handshake_segment_finish2);
            } else {
                ws_message_handle->on_append_header_value(ch);
            }
            break;
        }
        
        default:
            break;
        }
    }

    return pos;
}

}
