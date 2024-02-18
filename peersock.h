#pragma once

#include <string>
#include <functional>

#include <openssl/ssl.h>

#include "utils.h"

struct ModeBase {
    virtual void quicPoll() {};

    virtual int handleQuicStreamOpened(SSL *stream) {
        (void)stream;
        fatal("Unexpected stream\n");

        return 0;
    }

    virtual void connectionMade(std::function<void()> tick, SSL *connection) {};
};


void startFromCode(const std::string &code, std::unique_ptr<ModeBase> &&mode_);
void startGeneratingCode(std::function<void(std::string)> codeCallback, std::unique_ptr<ModeBase> &&mode_);