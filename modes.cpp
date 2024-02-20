#include "modes.h"

#include <glib.h>
#include <gio/gunixoutputstream.h>
#include <gio/gunixinputstream.h>

#include "utils.h"


SslToOutputStreamForwarder::SslToOutputStreamForwarder(std::function<void()> tick, SSL *ssl_stream, GOutputStream *output_stream)
    : _tick(tick), _ssl_stream(ssl_stream), _output_stream(output_stream) {

}

void SslToOutputStreamForwarder::quicPoll() {
    if (!_buffer_busy) {
        log(LOG_FWD, "Looking for data...\n", read);
        int read = quicReadOrDie(_ssl_stream, (char*)_buffer.data(), _buffer.size());

        if (read) {
            _buffer_busy = true;
            log(LOG_FWD, "Got {} bytes data from bridge.\n", read);
            auto callback = [](GObject* source_object, GAsyncResult* res, gpointer data) {
                (void)source_object;
                auto that = reinterpret_cast<SslToOutputStreamForwarder*>(data);

                gsize bytesWritten = -1;
                GError *error = nullptr;
                bool ok = g_output_stream_write_all_finish(that->_output_stream, res, &bytesWritten, &error);
                if (!ok) {
                    fatal("local write failed: after {} bytes: {}\n", bytesWritten, error->message);
                }
                if (bytesWritten != that->_buffer_used) {
                    fatal("local write failed to write all bytes {} != {}\n", bytesWritten, that->_buffer_used);
                }

                that->_buffer_busy = false;
                log(LOG_FWD, "Buffer idle again.\n");
                that->_tick();
            };
            _buffer_used = read;
            g_output_stream_write_all_async(_output_stream, _buffer.data(), read, G_PRIORITY_DEFAULT,
                                            nullptr, callback, this);
        }
    }
}

InputStreamToSslForwarder::InputStreamToSslForwarder(std::function<void()> tick, GInputStream *input_stream, SSL *ssl_stream)
    : _tick(tick), _input_stream(input_stream), _ssl_stream(ssl_stream) {
    startAsyncRead();

}

void InputStreamToSslForwarder::quicPoll() {
    if (_buffer_filled) {
        size_t written = -1;
        int ret = SSL_write_ex(_ssl_stream, _buffer.data() + _buffer_transmitted,
                               _buffer_filled - _buffer_transmitted,
                               &written);
        if (ret > 0) {
            if (written) {
                _buffer_transmitted += written;
                if (_buffer_filled == _buffer_transmitted) {
                    _buffer_filled = 0;
                    _buffer_transmitted = 0;
                    startAsyncRead();
                }
            } else {
                // Workaround for https://github.com/openssl/openssl/issues/23606
                //log(LOG_QUIC, "Successful write, but written 0 bytes, tried to write {} bytes\n", _buffer_filled - _buffer_transmitted);
            }
        } else {
            log(LOG_QUIC, "write data: len={}\n", _buffer_filled - _buffer_transmitted);
            int ssl_error = SSL_get_error(_ssl_stream, written);
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                fatal_ossl("write failed:\n");
            }
        }
    }
}

void InputStreamToSslForwarder::localReadCallback(GObject *source_object, GAsyncResult *res) {
    (void)source_object;
    gssize read = g_input_stream_read_finish(_input_stream, res, nullptr);
    log(LOG_FWD, "FWD: read finished\n");

    if (read == 0) {
        fmt::print(stderr, "connection close\n");
        // TODO
        exit(0);
    }

    //log(LOG_FWD, "read local input: {}\n", std::string_view((const char*)_buffer.data(), read));
    log(LOG_FWD, "read local input: {}\n", read);

    size_t written;
    int ret = SSL_write_ex(_ssl_stream, _buffer.data(), read, &written);
    log(LOG_FWD, "write returned {} and wrote {} bytes\n", ret, written);
    if (ret == 1) {
        // written can be == 0 here, see https://github.com/openssl/openssl/issues/23606
        if (written != read) {
            _buffer_filled = read;
            _buffer_transmitted = written;
        }
    } else {
        int ssl_error = SSL_get_error(_ssl_stream, written);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
            fatal_ossl("write failed:\n");
        }
    }

    _tick();
    if (!_buffer_filled) {
        startAsyncRead();
    }
}

void InputStreamToSslForwarder::wrap_localReadCallback(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    reinterpret_cast<InputStreamToSslForwarder*>(user_data)->localReadCallback(source_object, res);
}

void InputStreamToSslForwarder::startAsyncRead() {
    log(LOG_FWD, "FWD: read started\n");
    g_input_stream_read_async(_input_stream,
                              _buffer.data(), _buffer.size(),
                              G_PRIORITY_DEFAULT, nullptr, wrap_localReadCallback, this);
}

ListenMode::ListenMode(uint16_t port) : _port(port) {
    _listener = g_socket_listener_new();
    g_socket_listener_add_inet_port(_listener, _port, nullptr, nullptr);
    g_socket_listener_accept_async(_listener, nullptr, wrap_acceptCallback, this);
}

void ListenMode::connectionMade(std::function<void()> tick, SSL *connection) {
    _tick = tick;
    q_connection = connection;
    _bridged = true;
    if (_localConnection) {
        fatal("Code for local connection before quic auth not yet done");
        socket_to_ssl_forwarder.emplace(_tick, _localInputStream, _bridgeStream);
    }
}

int ListenMode::handleQuicStreamOpened(SSL *stream) {
    fatal("Unexpected stream\n");

    return 0;
}

void ListenMode::quicPoll() {
    if (socket_to_ssl_forwarder) {
        socket_to_ssl_forwarder->quicPoll();
    }
    if (ssl_to_socket_forwarder) {
        ssl_to_socket_forwarder->quicPoll();
    }
}

void ListenMode::acceptCallback(GObject *source_object, GAsyncResult *res) {
    if (_localConnection) {
        fmt::print(stderr, "Error: Only one connection implemented.\n");
        return;
    }
    (void)source_object;
    _localConnection = g_socket_listener_accept_finish(_listener, res, nullptr, nullptr);
    if (_localConnection) {
        _localInputStream = g_io_stream_get_input_stream((GIOStream*)_localConnection);
        _localOutputStream = g_io_stream_get_output_stream((GIOStream*)_localConnection);
        auto remoteAddr = g_socket_connection_get_remote_address(_localConnection, nullptr);
        auto remoteInetAddr = g_inet_socket_address_get_address((GInetSocketAddress*)remoteAddr);
        log(LOG_FWD, "Incoming connection from {}:{}\n", g_inet_address_to_string(remoteInetAddr),
            g_inet_socket_address_get_port((GInetSocketAddress*)remoteAddr));
        if (_bridged) {
            _bridgeStream = SSL_new_stream(q_connection, 0);
            if (!_bridgeStream) {
                fatal_ossl("SSL_new_stream for bridging:\n");
            }
            // Stream open only is send if data is written to the stream
            size_t written = -1;
            int ret = SSL_write_ex(_bridgeStream, "X", 1, &written);
            if (ret != 1 || written != 1) {
                fatal_ossl("Failed in initial write to payload stream:\n");
            }

            SSL_set_mode(_bridgeStream, SSL_MODE_ENABLE_PARTIAL_WRITE);
            socket_to_ssl_forwarder.emplace(_tick, _localInputStream, _bridgeStream);
            ssl_to_socket_forwarder.emplace(_tick, _bridgeStream, _localOutputStream);
            _tick();
        }
    } else {
        log(LOG_FWD, "accpet failed\n");
    }
}

void ListenMode::wrap_acceptCallback(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    reinterpret_cast<ListenMode*>(user_data)->acceptCallback(source_object, res);
}

ConnectMode::ConnectMode(std::string hostAndPort) : _hostAndPort(hostAndPort) {
    _socketClient = g_socket_client_new();
}

void ConnectMode::connectionMade(std::function<void()> tick, SSL *connection) {
    _tick = tick;
    q_connection = connection;
    _bridged = true;
    g_socket_client_connect_to_host_async(_socketClient, _hostAndPort.data(), 443, nullptr,
                                          wrap_localConnectCallback, this);
}

int ConnectMode::handleQuicStreamOpened(SSL *stream) {
    _bridgeStream = stream;
    SSL_set_mode(_bridgeStream, SSL_MODE_ENABLE_PARTIAL_WRITE);
    char buf[1];
    size_t readbytes = -1;
    int ret = SSL_read_ex(_bridgeStream, buf, 1, &readbytes);
    if (ret != 1) {
        fatal_ossl("initial read on payload stream failed:\n");
    }
    if (readbytes != 1) {
        fatal("initial read on payload stream wrong sizes: {}\n", readbytes);
    }
    if (buf[0] != 'X') {
        fatal("initial read on payload stream unexpected data: {}\n", buf[0]);
    }
    _ssl_to_socket_forwarder.emplace(_tick, _bridgeStream, _localOutputStream);
    _socket_to_ssl_forwarder.emplace(_tick, _localInputStream, _bridgeStream);
    return 0;
}

void ConnectMode::quicPoll() {
    if (_ssl_to_socket_forwarder) {
        _ssl_to_socket_forwarder->quicPoll();
    }
    if (_socket_to_ssl_forwarder) {
        _socket_to_ssl_forwarder->quicPoll();
    }
}

void ConnectMode::localConnectCallback(GObject *source_object, GAsyncResult *res) {
    (void)source_object;
    GError *error = nullptr;
    _localConnection = g_socket_client_connect_to_host_finish(_socketClient, res, &error);
    if (error) {
        fatal("Error: {}\n", error->message);
        g_error_free(error);
        return;
    }

    _localOutputStream = g_io_stream_get_output_stream((GIOStream*)_localConnection);
    _localInputStream = g_io_stream_get_input_stream((GIOStream*)_localConnection);
}

void ConnectMode::wrap_localConnectCallback(GObject *source_object, GAsyncResult *res, gpointer user_data) {
    reinterpret_cast<ConnectMode*>(user_data)->localConnectCallback(source_object, res);
}

StdioModeA::StdioModeA() {
}

void StdioModeA::connectionMade(std::function<void ()> tick, SSL *connection) {
    _tick = tick;
    q_connection = connection;
    _bridged = true;

    _localOutputStream = g_unix_output_stream_new(1, false);
    _localInputStream = g_unix_input_stream_new(0, false);
}

int StdioModeA::handleQuicStreamOpened(SSL *stream) {
    _bridgeStream = stream;
    SSL_set_mode(_bridgeStream, SSL_MODE_ENABLE_PARTIAL_WRITE);
    char buf[1];
    size_t readbytes = -1;
    int ret = SSL_read_ex(_bridgeStream, buf, 1, &readbytes);
    if (ret != 1) {
        fatal_ossl("initial read on payload stream failed:\n");
    }
    if (readbytes != 1) {
        fatal("initial read on payload stream wrong sizes: {}\n", readbytes);
    }
    if (buf[0] != 'X') {
        fatal("initial read on payload stream unexpected data: {}\n", buf[0]);
    }
    _ssl_to_socket_forwarder.emplace(_tick, _bridgeStream, _localOutputStream);
    _socket_to_ssl_forwarder.emplace(_tick, _localInputStream, _bridgeStream);
    return 0;
}

void StdioModeA::quicPoll() {
    if (_ssl_to_socket_forwarder) {
        _ssl_to_socket_forwarder->quicPoll();
    }
    if (_socket_to_ssl_forwarder) {
        _socket_to_ssl_forwarder->quicPoll();
    }
}

StdioModeB::StdioModeB() {
}

void StdioModeB::connectionMade(std::function<void ()> tick, SSL *connection) {
    _tick = tick;
    q_connection = connection;
    _bridged = true;

    _bridgeStream = SSL_new_stream(q_connection, 0);
    if (!_bridgeStream) {
        fatal_ossl("SSL_new_stream for bridging:\n");
    }
    // Stream open only is send if data is written to the stream
    size_t written = -1;
    int ret = SSL_write_ex(_bridgeStream, "X", 1, &written);
    if (ret != 1 || written != 1) {
        fatal_ossl("Failed in initial write to payload stream:\n");
    }

    SSL_set_mode(_bridgeStream, SSL_MODE_ENABLE_PARTIAL_WRITE);

    _localOutputStream = g_unix_output_stream_new(1, false);
    _localInputStream = g_unix_input_stream_new(0, false);

    _ssl_to_socket_forwarder.emplace(_tick, _bridgeStream, _localOutputStream);
    _socket_to_ssl_forwarder.emplace(_tick, _localInputStream, _bridgeStream);
}

int StdioModeB::handleQuicStreamOpened(SSL *stream) {
    fatal("Unexpected stream\n");

    return 0;
}

void StdioModeB::quicPoll() {
    if (_ssl_to_socket_forwarder) {
        _ssl_to_socket_forwarder->quicPoll();
    }
    if (_socket_to_ssl_forwarder) {
        _socket_to_ssl_forwarder->quicPoll();
    }
}
