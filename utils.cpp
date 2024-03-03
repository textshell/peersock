#include "utils.h"

#include <unistd.h>

#include <openssl/ssl.h>

int logEnabled = 0
        // | LOG_REND
        // | LOG_ICE
        // | LOG_QUIC
        // | LOG_AUTH
        // | LOG_FWD
        ;

bool peersockJsonOutputMode;

void setJsonOutputMode(bool val) {
    peersockJsonOutputMode = val;
}


int quicReadOrDie(SSL *stream, char *buf, int len) {
    int ret = 0;

    ret = SSL_read(stream, buf, len);
    if (ret <= 0) {
        int ssl_error = SSL_get_error(stream, ret);
        if (ssl_error == SSL_ERROR_WANT_READ) {
            return 0;
        } else if (ssl_error == SSL_ERROR_WANT_WRITE) {
            return 0;
        } else {
            fatal_ossl("quicReadOrDie failed\n");
        }
    }

    return ret;
}

void printToStdErr(char *data, int len) {
    write(2, data, len);
}
