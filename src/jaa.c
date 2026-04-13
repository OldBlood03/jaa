#include "jaa.h"
#include "darray.h"
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <libssh/libssh.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

//config file parser constants
#define TOKEN_HOSTS    "[hosts]"
#define TOKEN_USERNAME "[username]"
#define TOKEN_CMD      "[cmd]"
#define TOKEN_COMMENT  "//"

#define NULL_TERMINATOR 1

#define FILENAME "dist.jaa"

static void host_printf(host *h, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(h->status_buffer, sizeof(h->status_buffer), fmt, args);
    va_end(args);
}

static int host_authenticate(host *h)
{
    int auth_code;
    ssh_session session = h->session;

    host_printf(h, "trying authentication method: none");
    auth_code = ssh_userauth_none(session, NULL);
    switch (auth_code)
    {
        case SSH_AUTH_SUCCESS:
            host_printf(h, "authentication succeeded");
            return SSH_OK;
        default:
            host_printf(h, "authentication failed");
    }

    int supported_auth_methods = ssh_userauth_list(session, NULL);
    int method_pubkey   = SSH_AUTH_METHOD_PUBLICKEY  & supported_auth_methods;
    int method_password = SSH_AUTH_METHOD_PASSWORD   & supported_auth_methods;
    int method_gssapi   = SSH_AUTH_METHOD_GSSAPI_MIC & supported_auth_methods;

    if (method_gssapi)
    {
        host_printf(h, "trying authentication method: gssapi");
        auth_code = ssh_userauth_gssapi(session);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                host_printf(h, "authentication succeeded");
                return JAA_OK;
            default:
                host_printf(h, "authentication failed");
        }
    } 
    if (method_pubkey)
    {
        host_printf(h, "trying authentication method: ssh key");
        auth_code = ssh_userauth_publickey_auto(session, NULL, NULL);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                host_printf(h, "authentication succeeded");
                return JAA_OK;
            default:
                host_printf(h, "authentication failed");
        }
    } 
    if (method_password)
    {
        host_printf(h, "trying authentication method: password");
        char *password = getpass("password: ");
        auth_code = ssh_userauth_password(session, NULL, password);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                host_printf(h, "authentication succeeded");
                return JAA_OK;
            default:
                host_printf(h, "authentication failed");
        }
    } 

    host_printf(h, "no authentication possible");
    return SSH_ERROR;
}


static int host_verify_knownhost(host *h)
{
    ssh_session session = h->session;
    enum ssh_known_hosts_e state;
    ssh_key srv_pubkey = NULL;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return SSH_ERROR;
    }
    ssh_key_free(srv_pubkey);
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            host_printf(h, "host key for server changed. for security reasons, connection will be stopped");
            return SSH_ERROR;
        case SSH_KNOWN_HOSTS_OTHER:
            host_printf(h, "The host key for this server was not found but an other"
                    "type of key exists.");
            return SSH_ERROR;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            host_printf(h, "Could not find known host file.");
            host_printf(h, "If you accept the host key here, the file will be"
                    "automatically created.");
            [[fallthrough]];
        case SSH_KNOWN_HOSTS_UNKNOWN:
            host_printf(h, "The server is unknown. Trusting without asking.");
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                return SSH_ERROR;
            }
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            host_printf(h, "Error %s", ssh_get_error(session));
            return SSH_ERROR;
    }
    return SSH_OK;
}

static void host_channel_free(host *h)
{
    if (ssh_channel_is_open(h->channel))
        ssh_channel_close(h->channel);
    if (h->channel != NULL)
        ssh_channel_free(h->channel);
}

static void host_session_free(host *h)
{
    if (ssh_is_connected(h->session))
        ssh_disconnect(h->session);
    if (h->session != NULL)
        ssh_free(h->session);
}

static void host_free(host *h)
{
    host_channel_free(h);
    host_session_free(h);
}

static void host_init(host *h, const char *username)
{
    int rc;
    const long timeout = 2;
    const char *addr = h->addr;
    ssh_session session = ssh_new();
    h->session = session;

    if (session == NULL)
    {
        host_printf(h, "error: %s", ssh_get_error(session));
        goto err;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, (void *)addr);
    if (rc < 0)
    {
        host_printf(h, "error: %s", ssh_get_error(session));
        goto err;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_USER, (void *)username);
    if (rc < 0)
    {
        host_printf(h, "error: %s", ssh_get_error(session));
        goto err;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_TIMEOUT, (void *)&timeout);
    if (rc < 0)
    {
        host_printf(h, "error: %s", ssh_get_error(session));
        goto err;
    }

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        host_printf(h, "unable to connect");
        goto err;
    }

    rc = host_authenticate(h);
    if (rc != SSH_OK) {
        host_printf(h, "unable to authenticate host");
        goto err;
    }

    rc = host_verify_knownhost(h);
    if (rc != SSH_OK) {
        host_printf(h, "unable to verify host");
        goto err;
    }

    h->is_usable = true;
    return;
err:
    host_session_free(h);
    return;
}

static void host_exec(host *h, const char *cmd)
{
    host_channel_free(h);

    int rc;
    ssh_channel channel = ssh_channel_new(h->session);
    if (channel == NULL)
    {
        host_printf(h, "error: could not create ssh channel.");
        goto err;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        host_printf(h, "unable to open session");
        ssh_channel_free(channel);
        goto err;
    }

    h->channel = channel;
    host_printf(h, "executing command %s", cmd);
    rc = ssh_channel_request_exec(channel, cmd);
    if (rc == SSH_ERROR)
    {
        goto err;
        host_printf(h, "command failed");
    }

    return;
err:
    host_channel_free(h);
    return;
}

void host_read_io(host *h)
{
    int n_bytes;
    ssh_channel channel = h->channel;
    if (!ssh_channel_is_open(channel)) return;

    n_bytes = ssh_channel_read(channel, h->stdout_buffer, sizeof(h->stdout_buffer) - 1, 0);
    if (n_bytes == SSH_ERROR) return;
    h->stdout_buffer[n_bytes] = '\0';

    n_bytes = ssh_channel_read(channel, h->stderr_buffer, sizeof(h->stderr_buffer) - 1, 1);
    if (n_bytes == SSH_ERROR) return;
    h->stderr_buffer[n_bytes] = '\0';
    return;
}

static void remove_unusable_hosts(darray(host) pool)
{
    int n_hosts = darray_size(pool);
    for (int i = 0; i < n_hosts; i++)
    {
        if (!pool[i].is_usable)
        {
            darray_remove(pool, i);
            i--;
            n_hosts--;
        }
    }
}

void jaa_job_update(job *j)
{
    remove_unusable_hosts(j->pool);
    int n_hosts = darray_size(j->pool);
    for (int i = 0; i < n_hosts; i++)
    {
        if (!j->pool[i].is_usable) continue;
        if (!j->pool[i].is_busy && darray_size(j->cmds) > 0)
        {
            char *cmd = darray_pop(j->cmds);
            host_exec(&j->pool[i], cmd);
            free(cmd);
            j->pool[i].is_busy = true;
        }

        if (j->pool[i].is_busy && !ssh_channel_is_open(j->pool[i].channel))
            j->pool[i].is_busy = false;
        host_read_io(&j->pool[i]);
    }
}

bool jaa_job_should_shutdown(const job *j)
{
    for(int i = 0; i < darray_size(j->pool); i++)
        if (j->pool[i].is_busy || darray_size(j->cmds) > 0) 
            return false;
    return true;
}

job jaa_job_create()
{
    darray(host) pool = NULL;
    darray(char *) cmds = NULL;
    darray_alloc(pool);
    darray_alloc(cmds);
    return (job){.pool = pool, .cmds = cmds};
}

int jaa_job_init(job *out)
{
    FILE *fp;
    fp = fopen(FILENAME, "r");

    if (!fp)
    {
        perror("error opening file");
        return JAA_ERROR;
    }

    enum {
        NONE,
        HOSTS,
        USERNAME,
        CMD,
    } parser_state;
    parser_state = NONE;

    int    line_count = 0;
    size_t line_len = 0;
    char  *line_ptr = NULL;

    while(getline(&line_ptr, &line_len, fp) != EOF)
    {
        line_count ++;
        char *comment_start = strstr(line_ptr, TOKEN_COMMENT);
        bool commented;
        char *token;

        token = strstr(line_ptr, TOKEN_HOSTS);
        commented = (comment_start) && (token > comment_start);
        if(token && !commented) 
        { 
            parser_state = HOSTS;
            continue; 
        }

        token = strstr(line_ptr, TOKEN_USERNAME);
        commented = (comment_start) && (token > comment_start);
        if(token && !commented) 
        {
            parser_state = USERNAME;
            continue; 
        }

        token = strstr(line_ptr, TOKEN_CMD);
        commented = (comment_start) && (token > comment_start);
        if(token && !commented) 
        {
            parser_state = CMD;
            continue;
        }

        char *ptr;
        size_t trimmed_len;

        ptr = line_ptr;
        while (*ptr == ' ' || *ptr == '\t') ptr++;
        ptr = strtok(ptr, "\n");

        if (ptr == NULL) continue;
        if (comment_start != NULL) *comment_start = '\0';
        if (comment_start != NULL && ptr >= comment_start) continue;
        trimmed_len = strlen(ptr) + 1;

        switch(parser_state)
        {
            case NONE:
                break;
            case HOSTS:
                if (trimmed_len > MAX_ADDR_LEN) 
                {
                    fprintf(stderr, "parse error on line %d: encountered address that exceeds maximum "
                    "length:\naddress:%s\nmaxlen:%d\n",
                            line_count,
                            ptr, 
                            MAX_ADDR_LEN);
                    fclose(fp);
                    return JAA_ERROR;
                }

                host h = {0};
                strcpy(h.addr, ptr);
                darray_push_back(out->pool, h);
                break;
            case USERNAME:
                if (trimmed_len > MAX_USERNAME_LEN) 
                {
                    fprintf(stderr,
                            "parse error on line %d: encountered username that exceeds maximum length:\nusername:%s\nmaxlen:%d\n",
                            line_count,
                            ptr, 
                            MAX_USERNAME_LEN);
                    fclose(fp);
                    return JAA_ERROR;
                }
                if (*out->username)
                {
                    fprintf(stderr, "parse error on line %d: multiple usernames given\n", line_count);
                    fclose(fp);
                    return JAA_ERROR;
                }
                strcpy(out->username, ptr);
                break;
            case CMD:
                char *cmd = strdup(ptr);
                darray_push_back(out->cmds, cmd);
                break;
        }
    }

    if (!(*out->username))
    {
        fprintf(stderr, "no username supplied in config file\n");
        fclose(fp);
        return JAA_ERROR;
    }

    fclose(fp);
    free(line_ptr);
#pragma omp parallel for
    for (int i = 0; i < darray_size(out->pool); i++)
    {
        host_init(&out->pool[i], out->username);
    }
    return JAA_OK;
}

void jaa_job_destroy(job *in)
{
    for (int i = 0; i < darray_size(in->cmds); i++)
        free(in->cmds[i]);
    darray_free(in->cmds);
    for (int i = 0; i < darray_size(in->pool); i++)
        host_free(&in->pool[i]);
    darray_free(in->pool);
}
