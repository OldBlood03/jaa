#ifndef JAA
#define JAA
#include <libssh/libssh.h>
#include <stdbool.h>
#include "table.h"

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

    int  progress_num, progress_denom;
    int  n_exits;
    bool is_usable;
    bool is_busy;
    int  id;
} host;

int  find_config_file(char *filename_out, size_t capacity);
int  init_config_from_file(const char *filename);
void distribute(table_style style);
#endif//JAA
