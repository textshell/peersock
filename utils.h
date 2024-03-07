#pragma once

#include <chrono>
#include <optional>

#include <openssl/err.h>

#include <nlohmann/json.hpp>

#include <fmt/core.h>


extern int logEnabled;
extern bool peersockJsonOutputMode;

const int LOG_REND = 1 << 0;
const int LOG_ICE = 1 << 1;
const int LOG_QUIC = 1 << 2;
const int LOG_AUTH = 1 << 3;
const int LOG_FWD = 1 << 4;

void setJsonOutputMode(bool val);

void printToStdErr(char *data, int len);

template <typename T, typename ...P>
void log(int category, T &&format, P &&... params) {
    if (category & logEnabled) {
        std::string message;

        std::string formatted = fmt::format(std::forward<T>(format), std::forward<P>(params)...);

        if (peersockJsonOutputMode) {
            std::string categoryName;

            if (category == LOG_REND) {
                categoryName = "REND: ";
            } else if (category == LOG_ICE) {
                categoryName = "ICE: ";
            } else if (category == LOG_QUIC) {
                categoryName = "QUIC: ";
            } else if (category == LOG_AUTH) {
                categoryName = "AUTH: ";
            } else if (category == LOG_FWD) {
                categoryName = "FWD: ";
            }

            nlohmann::json msg = {
                {"log-category", categoryName},
                {"message", formatted},
            };
            message = msg.dump() + "\n";
        } else {
            message += fmt::format("{} ", std::chrono::system_clock::now().time_since_epoch().count());
            if (category == LOG_REND) {
                message += "REND: ";
            } else if (category == LOG_ICE) {
                message += "ICE: ";
            } else if (category == LOG_QUIC) {
                message += "QUIC: ";
            } else if (category == LOG_AUTH) {
                message += "AUTH: ";
            } else if (category == LOG_FWD) {
                message += "FWD: ";
            }
            message += formatted;
        }

        // not using fmt::print here because it throws exceptions, but we want to ignore errors in logging.
        printToStdErr(message.data(), message.length());
    }
}

template <typename T, typename ...P>
void fatal(T &&format, P &&... params) {
    std::string message = fmt::format(std::forward<T>(format), std::forward<P>(params)...);

    // not using fmt::print here because it throws exceptions, but we want to ignore errors in logging.
    printToStdErr(message.data(), message.length());
    exit(1);
}


template <typename T, typename ...P>
std::string fatal_ossl(T &&format, P &&... params) {
    std::string message = fmt::format(std::forward<T>(format), std::forward<P>(params)...);

    // not using fmt::print here because it throws exceptions, but we want to ignore errors in logging.
    printToStdErr(message.data(), message.length());

    ERR_print_errors_fp(stderr);
    exit(1);
}

template <typename T, typename ...P>
void writeUserMessage(nlohmann::json machineReadable, T &&format, P &&... params) {
    std::string message;
    std::string formatted = fmt::format(std::forward<T>(format), std::forward<P>(params)...);

    if (peersockJsonOutputMode) {
        machineReadable["message"] = formatted;
        message = machineReadable.dump() + "\n";
    } else {
        message = formatted;
    }

    // not using fmt::print here because it throws exceptions, but we want to ignore errors in logging.
    printToStdErr(message.data(), message.length());
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
