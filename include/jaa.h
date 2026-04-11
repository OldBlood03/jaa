#ifndef JAA
#define JAA
#include "darray.h"
#include <libssh/libssh.h>
#include <stdio.h>
#include <stdbool.h>

#define HOST_CAPACITY    128
#define MAX_ADDR_LEN     128
#define MAX_USERNAME_LEN 128
#define MAX_PATH_LEN     128
#define STDOUT_CAPACITY  128

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
    char relpath[MAX_PATH_LEN];
    darray(char *) cmds;
    darray(host)   pool;
} job;

job  jaa_job_create();
int  jaa_job_init(job *out);
bool jaa_job_should_shutdown();
void jaa_job_update(job j);
void jaa_job_destroy(job in);

#endif//JAA
