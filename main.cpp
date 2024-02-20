#include <charconv>

#include <glib.h>

#include "modes.h"
#include "peersock.h"
#include "utils.h"

using namespace std::string_literals;


int main(int argc, char **argv) {
    /*
    // Test code for secret possession proof code
    OtrlSMState alice;
    OtrlSMState bob;

    otrl_sm_state_new(&alice);
    otrl_sm_state_new(&bob);

    unsigned char *buf1Ptr = nullptr;
    int buf1Len = 0;

    unsigned char *buf2Ptr = nullptr;
    int buf2Len = 0;

    if (otrl_sm_step1(&alice, (const unsigned char*)"secret", 6, &buf1Ptr, &buf1Len) != gcry_error(GPG_ERR_NO_ERROR)) {
        log(LOG_AUTH, "otrl_sm_step1 failed\n");
    }
    log(LOG_AUTH, "size: {}\n", buf1Len);
    if (otrl_sm_step2a(&bob, buf1Ptr, buf1Len, 0) != gcry_error(GPG_ERR_NO_ERROR)) {
        log(LOG_AUTH, "otrl_sm_step2a failed\n");
    }
    free(buf1Ptr);
    log(LOG_AUTH, "size: {}\n", buf1Len);
    if (otrl_sm_step2b(&bob, (const unsigned char*)"secret", 6, &buf1Ptr, &buf1Len) != gcry_error(GPG_ERR_NO_ERROR)) {
        log(LOG_AUTH, "otrl_sm_step2b failed\n");
    }
    log(LOG_AUTH, "size: {}\n", buf1Len);
    if (otrl_sm_step3(&alice, buf1Ptr, buf1Len, &buf2Ptr, &buf2Len) != gcry_error(GPG_ERR_NO_ERROR)) {
        log(LOG_AUTH, "otrl_sm_step3 failed\n");
    }
    free(buf1Ptr);
    log(LOG_AUTH, "size: {}\n", buf2Len);
    if (otrl_sm_step4(&bob, buf2Ptr, buf2Len, &buf1Ptr, &buf1Len) != gcry_error(GPG_ERR_NO_ERROR)) {
        log(LOG_AUTH, "otrl_sm_step4 failed\n");
    }
    free(buf2Ptr);
    log(LOG_AUTH, "size: {}\n", buf1Len);
    if (otrl_sm_step5(&alice, buf1Ptr, buf1Len) != gcry_error(GPG_ERR_NO_ERROR)) {
        log(LOG_AUTH, "otrl_sm_step5 failed\n");
    }
    log(LOG_AUTH, "size: {}\n", buf1Len);
    free(buf1Ptr);

    otrl_sm_state_free(&alice);
    otrl_sm_state_free(&bob);
    return 0;
    */

    std::string code;
    std::unique_ptr<ModeBase> mode;


    bool ok = false;
    if (argc == 3 || argc == 4) {
        std::string arg = argv[2];
        if (argv[1] == "listen"s) {
            uint16_t port;

            auto [ptr, ec] = std::from_chars(arg.data(), arg.data() + arg.size(), port);
            if (ec == std::errc{}) {
                ok = true;
                mode = std::make_unique<ListenMode>(port);
            } else {
                fatal("Can't parse port '{}'\n", arg);
            }
        } else if (argv[1] == "connect"s) {
            ok = true;
            mode = std::make_unique<ConnectMode>(arg);
        } else if (argv[1] == "stdio-a"s) {
            ok = true;
            mode = std::make_unique<StdioModeA>();
        } else if (argv[1] == "stdio-b"s) {
            ok = true;
            mode = std::make_unique<StdioModeB>();
        }

        if (argc == 4) {
            if (std::string(argv[3]).find_first_of('-') == std::string::npos) {
                fatal("Code format invalid\n");
            }
            code = argv[3];
        } else {
        }
    }

    if (!ok) {
        fmt::print(stderr, "Usage: {} listen port [connect code]\n", argv[0]);
        fmt::print(stderr, "       {} connect host:port [connect code]\n", argv[0]);
        return 1;
    }

    static GMainLoop *mainLoop = g_main_loop_new (NULL, TRUE);

    if (code.size()) {
        startFromCode(code, std::move(mode));
    } else {
        startGeneratingCode([](const std::string &generated_code) {
            fmt::print(stderr, "Connection Code is: {}\n", generated_code);
        }, std::move(mode));
    }


    g_main_loop_run (mainLoop);
    g_main_loop_unref (mainLoop);

    return 0;
}
