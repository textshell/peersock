#include <charconv>

#include <glib.h>

#include "modes.h"
#include "peersock.h"
#include "utils.h"

using namespace std::string_literals;


void applyConfig(PeersockConfig &config) {
    GKeyFile *configFile = g_key_file_new();
    GError *error = nullptr;

    char *configFilename = g_build_filename(g_get_user_config_dir(), "peersock.conf", nullptr);

    bool loaded = g_key_file_load_from_file(configFile,
                                       configFilename,
                                       G_KEY_FILE_NONE, &error);

    if (!loaded) {
        if (!g_error_matches(error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
            g_printerr("%s parsing failed: %s\n", configFilename, error->message);
        }
        return;
    }
    const char *stunServer = g_key_file_get_string(configFile, "ice", "stun", &error);

    if (error) {
        if (!g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)
            && !g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {

            g_printerr("error getting stun server from config: %s\n", error->message);
            return;
        } else {
            g_clear_error(&error);
        }
    } else if (config.stunServer.empty() && stunServer && *stunServer) {
        config.stunServer = stunServer;
    }

    int tmp = g_key_file_get_integer(configFile, "ice", "stun-port", &error);

    if (error) {
        if (!g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)
            && !g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {

            g_printerr("error getting stun-port from config: %s\n", error->message);
            return;
        } else {
            g_clear_error(&error);
        }
    } else {
        if (!config.stunPort) {
            config.stunPort = tmp;
        }
    }

    const char *turnServer = g_key_file_get_string(configFile, "ice", "turn", &error);

    if (error) {
        if (!g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)
            && !g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {

            g_printerr("error getting turn server from config: %s\n", error->message);
            return;
        } else {
            g_clear_error(&error);
        }
    } else if (config.turnServer.empty() && turnServer && *turnServer) {
        config.turnServer = turnServer;
    }

    tmp = g_key_file_get_integer(configFile, "ice", "turn-port", &error);

    if (error) {
        if (!g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)
            && !g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {

            g_printerr("error getting turn-port from config: %s\n", error->message);
            return;
        } else {
            g_clear_error(&error);
        }
    } else {
        if (!config.turnPort) {
            config.turnPort = tmp;
        }
    }

    const char *turnUser = g_key_file_get_string(configFile, "ice", "turn-user", &error);

    if (error) {
        if (!g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)
            && !g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {

            g_printerr("error getting turn-user from config: %s\n", error->message);
            return;
        } else {
            g_clear_error(&error);
        }
    } else if (config.turnUser.empty() && turnUser && *turnUser) {
        config.turnUser = turnUser;
    }

    const char *turnPassword = g_key_file_get_string(configFile, "ice", "turn-password", &error);

    if (error) {
        if (!g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)
            && !g_error_matches(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {

            g_printerr("error getting turn-password from config: %s\n", error->message);
            return;
        } else {
            g_clear_error(&error);
        }
    } else if (config.turnPassword.empty() && turnPassword && *turnPassword) {
        config.turnPassword = turnPassword;
    }
}

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

    std::vector<std::string> remainingArgs;

    for (int i = 1; i < argc; i++) {
        if (argv[i] == "--json"s) {
            setJsonOutputMode(true);
        } else {
            remainingArgs.push_back(std::string(argv[i]));
        }
    }

    bool ok = false;
    if (remainingArgs.size()) {
        std::string command = remainingArgs[0];

        if (command == "listen"s && (remainingArgs.size() == 2 || remainingArgs.size() == 3)) {
            uint16_t port;

            std::string arg = remainingArgs[1];

            auto [ptr, ec] = std::from_chars(arg.data(), arg.data() + arg.size(), port);
            if (ec == std::errc{}) {
                ok = true;
                mode = std::make_unique<ListenMode>(port);
            } else {
                fatal("Can't parse port '{}'\n", arg);
            }

            if (remainingArgs.size() == 3) {
                code = remainingArgs[2];
            }
        } else if (command == "connect"s && (remainingArgs.size() == 2 || remainingArgs.size() == 3)) {
            ok = true;

            std::string arg = remainingArgs[1];

            mode = std::make_unique<ConnectMode>(arg);

            if (remainingArgs.size() == 3) {
                code = remainingArgs[2];
            }
        } else if (command == "stdio-a"s && (remainingArgs.size() == 1 || remainingArgs.size() == 2)) {
            ok = true;
            mode = std::make_unique<StdioModeA>();

            if (remainingArgs.size() == 2) {
                code = remainingArgs[1];
            }
        } else if (command == "stdio-b"s && (remainingArgs.size() == 1 || remainingArgs.size() == 2)) {
            ok = true;
            mode = std::make_unique<StdioModeB>();

            if (remainingArgs.size() == 2) {
                code = remainingArgs[1];
            }
        }

        if (code.size()) {
            if (std::string(code).find_first_of('-') == std::string::npos) {
                fatal("Code format invalid\n");
            }
        }
    }

    if (!ok) {
        fmt::print(stderr, "Usage: {} listen port [connect code]\n", argv[0]);
        fmt::print(stderr, "       {} connect host:port [connect code]\n", argv[0]);
        fmt::print(stderr, "       {} stdio-a [connect code]\n", argv[0]);
        fmt::print(stderr, "       {} stdio-b [connect code]\n", argv[0]);
        return 1;
    }

    static GMainLoop *mainLoop = g_main_loop_new (NULL, TRUE);


    PeersockConfig config;
    applyConfig(config);

    if (code.size()) {
        startFromCode(code, std::move(mode), config);
    } else {
        startGeneratingCode([](const std::string &generated_code) {
            writeUserMessage({
                                 {"event", "code-generated"},
                                 {"code", generated_code},
                             },
                             "Connection Code is: {}\n", generated_code);
        }, std::move(mode), config);
    }

    signal(SIGPIPE, SIG_IGN);

    g_main_loop_run (mainLoop);
    g_main_loop_unref (mainLoop);

    return 0;
}
