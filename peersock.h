#pragma once

#include <string>
#include <functional>

#include <openssl/ssl.h>

#include "utils.h"


struct PeersockConfig {
    std::string stunServer;
    std::optional<int> stunPort;
};


class RemoteConnection {
public:
    virtual SSL *ssl() = 0;
    virtual void shutdown() = 0;
};

struct ModeBase {
    virtual void quicPoll() {};

    virtual int handleQuicStreamOpened(SSL *stream) {
        (void)stream;
        fatal("Unexpected stream\n");

        return 0;
    }

    virtual void connectionMade(std::function<void()> tick, RemoteConnection *connection) {};
};


void startFromCode(const std::string &code, std::unique_ptr<ModeBase> &&mode_, PeersockConfig config);
void startGeneratingCode(std::function<void(std::string)> codeCallback, std::unique_ptr<ModeBase> &&mode_, PeersockConfig config);
