#ifndef DEFS
#define DEFS

#include <libssh/libssh.h>
#define HOST_CAPACITY    128
#define MAX_ADDR_LEN     128
#define MAX_USERNAME_LEN 128
#define MAX_PATH_LEN     128
#define MAX_CMD_LEN      128
#define MAX_ARG_LEN      128
#define STDOUT_CAPACITY  1024

typedef struct host {
    ssh_session session;
    ssh_channel channel;

    char addr       [MAX_ADDR_LEN];
    char log_file   [MAX_PATH_LEN];
    int  exit_codes [MAX_ARG_LEN];
    char stdout_buffer[STDOUT_CAPACITY];
    char stderr_buffer[STDOUT_CAPACITY];

    int  n_exits;
    bool is_usable;
    bool is_busy;
    int  pos;
} host;

#endif//DEFS
