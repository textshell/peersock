#pragma once

#include <chrono>

#include <openssl/err.h>

#include <fmt/core.h>


extern int logEnabled;

const int LOG_REND = 1 << 0;
const int LOG_ICE = 1 << 1;
const int LOG_QUIC = 1 << 2;
const int LOG_AUTH = 1 << 3;
const int LOG_FWD = 1 << 4;

template <typename T, typename ...P>
void log(int category, T &&format, P &&... params) {
    if (category & logEnabled) {
        fmt::print(stderr, "{} ", std::chrono::system_clock::now().time_since_epoch().count());
        if (category == LOG_REND) {
            fmt::print(stderr, "REND: ");
        } else if (category == LOG_ICE) {
            fmt::print(stderr, "ICE: ");
        } else if (category == LOG_QUIC) {
            fmt::print(stderr, "QUIC: ");
        } else if (category == LOG_AUTH) {
            fmt::print(stderr, "AUTH: ");
        } else if (category == LOG_FWD) {
            fmt::print(stderr, "FWD: ");
        }
        fmt::print(std::forward<T>(format), std::forward<P>(params)...);
    }
}

template <typename T, typename ...P>
void fatal(T &&format, P &&... params) {
    fmt::print(stderr, std::forward<T>(format), std::forward<P>(params)...);
    exit(1);
}


template <typename T, typename ...P>
std::string fatal_ossl(T &&format, P &&... params) {
    fmt::print(stderr, std::forward<T>(format), std::forward<P>(params)...);
    ERR_print_errors_fp(stderr);
    exit(1);
}

int quicReadOrDie(SSL *stream, char *buf, int len);

template <typename F>
void quicReadFramedMessageOrDie(SSL *stream, std::string &buf, F f) {

    char buf2[4096];

    if (buf.size() < 2) {
        int available = quicReadOrDie(stream, (char*)buf2, 2 - buf.size());
        if (available) {
            buf.append(buf2, available);
        }
        if (buf.size() < 2) {
            return;
        }
    }

    ssize_t frameLen = ((unsigned char*)buf.data())[0] << 8 | ((unsigned char*)buf.data())[1];

    int available = quicReadOrDie(stream, buf2, (frameLen + 2) - buf.size());
    if (available) {
        buf.append(buf2, available);
    }

    if (buf.size() < 2 + frameLen) {
        return;
    }

    f(((unsigned char*)buf.data()) + 2, frameLen);

    buf.resize(0);
}
