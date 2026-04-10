#ifndef JAA
#define JAA
#include "darray.h"
#include <libssh/libssh.h>
#include <stdio.h>
#include <stdbool.h>
#include "table.h"

#define HOST_CAPACITY    128
#define MAX_ADDR_LEN     128
#define MAX_USERNAME_LEN 128
#define MAX_PATH_LEN     128
#define STDOUT_CAPACITY  1024

#define JAA_ERROR SSH_ERROR
#define JAA_OK    SSH_OK

typedef struct host 
{
    ssh_session session;
    ssh_channel channel;

    char addr         [MAX_ADDR_LEN];
    char stdout_buffer[STDOUT_CAPACITY];
    char stderr_buffer[STDOUT_CAPACITY];
    char status_buffer[STDOUT_CAPACITY];

    bool is_usable;
    bool is_busy;
} host;

typedef struct job{
    char username[MAX_USERNAME_LEN];
    char relpath[];
    darray(const char *) cmds;
    darray(host)   pool;
} job;

int  jaa_job_init(job *out);
void jaa_job_free(job *in);
int  jaa_update(job j);

#endif//JAA
