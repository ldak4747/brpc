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

// brpc - A framework to host and access services throughout Baidu.

// Date: Thu Oct 15 21:08:31 CST 2015

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <memory>
#include <thread>
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <google/protobuf/descriptor.h>
#include "butil/containers/flat_map.h"
#include "butil/time.h"
#include "butil/macros.h"
#include "brpc/channel.h"
#include "brpc/socket.h"
#include "brpc/acceptor.h"
#include "brpc/server.h"
#include "brpc/policy/ws_rpc_protocol.h"
#include "brpc/policy/most_common_message.h"
#include "brpc/controller.h"
#include "brpc/policy/websocket.pb.h"

namespace {

brpc::Controller* g_controller = nullptr;
butil::IOBuf g_send_buf;
std::string g_msg;

class MyEchoService : public ::brpc::policy::WebSocketService {
    virtual void default_method(
        ::google::protobuf::RpcController* cntl,
        const ::brpc::policy::WebSocketRequest* req,
        ::brpc::policy::WebSocketResponse* res,
        ::google::protobuf::Closure* done) override {
        brpc::ClosureGuard done_guard(done);
        g_controller = reinterpret_cast<brpc::Controller*>(cntl);
        auto pa = g_controller->CreateProgressiveAttachment();
        if (!pa.get()) {
            delete g_controller;
            g_controller = nullptr;
            return;
        }
        pa->MarkRPCAsDone(false);

        int32_t idx = 0;
        while (1) {
            g_msg = std::to_string(idx++);
            if (!brpc::policy::PackWsMsgToIOBuf(
                    &g_send_buf, 1, 1, 0, g_msg.length(), "", g_msg.data())) {
                break;
            }

            int32_t ret = pa->Write(g_send_buf);
            if (ret) {
                LOG(ERROR) << "Write fail";
                break;
            }
            g_send_buf.clear();
            bthread_usleep(1000 * 1000);
        }

        delete g_controller;
        g_controller = nullptr;
    }
};

TEST(WebSocketTest, echo) {
    brpc::Server server;
    MyEchoService service;
    EXPECT_EQ(0, server.AddService(&service, brpc::SERVER_DOESNT_OWN_SERVICE));
    
    brpc::ServerOptions options;
    options.num_threads = 16;
    EXPECT_EQ(0, server.Start(8010, &options));
    server.RunUntilAskedToQuit();
}

class ServerTextPusher {
public:
    ServerTextPusher(::google::protobuf::RpcController* cntl) {
        controller = reinterpret_cast<brpc::Controller*>(cntl);
    }
    ~ServerTextPusher() {
        if (controller) {
            if (!send_buf.empty() && pa.get()) {
                pa->Write(send_buf);
            }

            send_buf.clear();
            delete controller;
            controller = nullptr;
        }
    }

    bool Init() {
        if (!controller) {
            return false;
        }

        pa = controller->CreateProgressiveAttachment();
        if (!pa.get()) {
            delete controller;
            controller = nullptr;
            return false;
        }
        pa->MarkRPCAsDone(false);
        return true;
    }

    int32_t Push(const char* payload, size_t length) {
        send_buf.clear();
        brpc::policy::PackWsMsgToIOBuf(&send_buf, 1, 1, 0, length, "", payload);
        return pa->Write(send_buf);
    }

    int32_t Push(const std::string& payload) {
        send_buf.clear();
        brpc::policy::PackWsMsgToIOBuf(
            &send_buf, 1, 1, 0, payload.length(), "", payload.data());
        return pa->Write(send_buf);
    }

private:
    brpc::Controller* controller = nullptr;
    butil::intrusive_ptr<brpc::ProgressiveAttachment> pa;
    butil::IOBuf send_buf;
};

bthread::Mutex mutex;
std::unordered_map<int64_t, std::unique_ptr<ServerTextPusher>> pusher_dict;

/*
    node.js client easy-test code could such as follow:
    """"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    var arguments = process.argv.splice(2);
    var uid = arguments[0]
    var str = "{\"uid\":" + uid + "}"

    function sleep (time) {
        return new Promise((resolve) => setTimeout(resolve, time));
    }

    const WebSocket = require('ws');
    const ws = new WebSocket('ws://localhost:8010');
    ws.onopen = async () => {
        console.log("WebSocket connect success!");
        await sleep(1000)
        ws.send(str)
    }

    ws.onmessage = function(e) {
        console.log("receive: " + e.data);
        ws.send(str)
    }

    ws.onclose = function() {
        console.log("close...")
    }
    """"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
*/

class MockService : public ::brpc::policy::WebSocketService {
    bool ParseUid(const std::string& msg, int64_t& uid) {
        auto pos = msg.find(':');
        if (pos == std::string::npos) {
            return false;
        }

        std::string uid_str = msg.substr(pos + 1);
        uid_str.pop_back();
        uid = std::stoll(uid_str);
        return true;
    }

    virtual void default_method(
        ::google::protobuf::RpcController* cntl,
        const ::brpc::policy::WebSocketRequest* req,
        ::brpc::policy::WebSocketResponse* res,
        ::google::protobuf::Closure* done) override {
        brpc::ClosureGuard done_guard(done);
        std::unique_ptr<ServerTextPusher> pusher;
        pusher.reset(new ServerTextPusher(cntl));

        int64_t uid;
        if (!ParseUid(req->message(), uid)) {
            return;
        }

        if (pusher->Init()) {
            std::unique_lock<bthread::Mutex> lock(mutex);
            if (pusher_dict.find(uid) == pusher_dict.end()) {
                pusher_dict[uid] = std::move(pusher);
                LOG(INFO) << "add client " << uid;
            } else {
                LOG(INFO) << "client " << uid << " already exist";
            }
        }
    }
};

TEST(WebSocketTest, clients_in_dict) {
    std::atomic<int> running;
    running.store(true);
    std::thread mock_use_thread([&](){
        std::string response;
        while (running.load()) {
            auto now = std::chrono::high_resolution_clock::now();
            int64_t ts = static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    now.time_since_epoch()).count());
            response = std::to_string(ts);
            std::unique_lock<bthread::Mutex> lock(mutex);
            for (auto it = pusher_dict.begin(); it != pusher_dict.end();) {
                if (it->second->Push(response)) {
                    LOG(INFO) << "erase client " << it->first;
                    pusher_dict.erase(it++);
                } else {
                    ++it;
                }
            }
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    brpc::Server server;
    MockService service;
    EXPECT_EQ(0, server.AddService(&service, brpc::SERVER_DOESNT_OWN_SERVICE));
    
    brpc::ServerOptions options;
    options.num_threads = 16;
    EXPECT_EQ(0, server.Start(8010, &options));
    server.RunUntilAskedToQuit();
    running.store(false);
    mock_use_thread.join();
}

}

int main(int argc, char* argv[]) {
    testing::InitGoogleTest(&argc, argv);
    GFLAGS_NS::ParseCommandLineFlags(&argc, &argv, true);
    return RUN_ALL_TESTS();
}
