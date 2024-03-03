#pragma once

#include <functional>

#include <openssl/ssl.h>

#include <glib.h>
#include <gio/gio.h>
//#include <libsoup/soup.h>

#include "utils.h"
#include "peersock.h"

class SslToOutputStreamForwarder {
public:
    SslToOutputStreamForwarder(std::function<void()> tick, SSL *ssl_stream, GOutputStream *output_stream);

    void quicPoll();

private:
    std::function<void()> _tick;
    SSL *_ssl_stream = nullptr;
    GOutputStream *_output_stream = nullptr;

    static constexpr size_t _bufferSize = 2*1024*1024;
    std::array<std::byte, _bufferSize> _buffer;
    int _buffer_used = 0;
    bool _buffer_busy = false;
};

class InputStreamToSslForwarder {
public:
    InputStreamToSslForwarder(std::function<void()> tick, GInputStream *input_stream, SSL *ssl_stream);

    void quicPoll();

    void localReadCallback(GObject *source_object, GAsyncResult *res);

    static void wrap_localReadCallback(GObject *source_object, GAsyncResult *res, gpointer user_data);

    void startAsyncRead();

    std::function<void()> onClose;

private:
    std::function<void()> _tick;
    GInputStream *_input_stream = nullptr;
    SSL *_ssl_stream = nullptr;

    std::array<std::byte, 1024*1024> _buffer;
    int _buffer_filled = 0;
    int _buffer_transmitted = 0;
};


struct ListenMode : public ModeBase {
    ListenMode(uint16_t port);

    void connectionMade(std::function<void()> tick, RemoteConnection *connection) override;

    int handleQuicStreamOpened(SSL *stream) override;

    void quicPoll() override;

    void acceptCallback(GObject *source_object, GAsyncResult *res);

    static void wrap_acceptCallback(GObject *source_object, GAsyncResult *res, gpointer user_data);

private:
    GSocketListener *_listener = nullptr;
    uint16_t _port = 0;
    GSocketConnection *_localConnection = nullptr;
    GInputStream *_localInputStream = nullptr;
    GOutputStream *_localOutputStream = nullptr;

    RemoteConnection *q_connection = nullptr;
    std::function<void()> _tick;
    bool _bridged = false;
    SSL *_bridgeStream = nullptr;

    std::optional<InputStreamToSslForwarder> socket_to_ssl_forwarder;
    std::optional<SslToOutputStreamForwarder> ssl_to_socket_forwarder;
};

struct ConnectMode : public ModeBase {
    ConnectMode(std::string hostAndPort);

    void connectionMade(std::function<void()> tick, RemoteConnection *connection) override;

    int handleQuicStreamOpened(SSL *stream) override;

    void quicPoll() override;


    void localConnectCallback(GObject *source_object, GAsyncResult *res);

    static void wrap_localConnectCallback(GObject *source_object, GAsyncResult *res, gpointer user_data);

private:
    std::string _hostAndPort;
    GSocketClient *_socketClient = nullptr;
    GSocketConnection *_localConnection = nullptr;
    GOutputStream *_localOutputStream = nullptr;
    GInputStream *_localInputStream = nullptr;
    std::optional<SslToOutputStreamForwarder> _ssl_to_socket_forwarder;
    std::optional<InputStreamToSslForwarder> _socket_to_ssl_forwarder;

    RemoteConnection *q_connection = nullptr;
    std::function<void()> _tick;
    bool _bridged = false;
    SSL *_bridgeStream = nullptr;
};

struct StdioModeA : public ModeBase {
    StdioModeA();

    void connectionMade(std::function<void()> tick, RemoteConnection *connection) override;
    int handleQuicStreamOpened(SSL *stream) override;
    void quicPoll() override;

private:
    GOutputStream *_localOutputStream = nullptr;
    GInputStream *_localInputStream = nullptr;
    std::optional<SslToOutputStreamForwarder> _ssl_to_socket_forwarder;
    std::optional<InputStreamToSslForwarder> _socket_to_ssl_forwarder;

    RemoteConnection *q_connection = nullptr;
    std::function<void()> _tick;
    bool _bridged = false;
    SSL *_bridgeStream = nullptr;
};

struct StdioModeB : public ModeBase {
    StdioModeB();

    void connectionMade(std::function<void()> tick, RemoteConnection *connection) override;
    int handleQuicStreamOpened(SSL *stream) override;
    void quicPoll() override;

private:
    GInputStream *_localInputStream = nullptr;
    GOutputStream *_localOutputStream = nullptr;

    RemoteConnection *q_connection = nullptr;
    std::function<void()> _tick;
    bool _bridged = false;
    SSL *_bridgeStream = nullptr;

    std::optional<InputStreamToSslForwarder> _socket_to_ssl_forwarder;
    std::optional<SslToOutputStreamForwarder> _ssl_to_socket_forwarder;
};
