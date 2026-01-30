#include<stdio.h>
#include<libssh/libssh.h>
#include<errno.h>
#include<stdarg.h>
#include<stdbool.h>
#include<string.h>

#define ANSI_CLEAR_LINE "\033[K"
#define ANSI_UP         "\033[%dA"
#define ANSI_DOWN       "\033[%dB"
#define ANSI_BEGIN      "\r"
#define ANSI_BLINK      "\033[5m"
#define ANSI_RED        "\033[38;5;9m"
#define ANSI_WHITE      "\033[38;5;15m"

#define HOST_CAPACITY    128
#define MAX_ADDR_LEN     128
#define MAX_USERNAME_LEN 128
#define MAX_PATH_LEN     128
#define MAX_CMD_LEN      128
#define MAX_ARG_LEN      128

//stdout progress parsing constants
//change these if u want, make sure they are not equal to each other
#define PROGRESS_START '{'
#define PROGRESS_END   '}'
#if PROGRESS_START == PROGRESS_END
    #error PROGRESS_START should != PROGRESS_END but does
#endif

//progress bar
#define PBAR_LEN 40
const char pbar [PBAR_LEN] = "########################################";
const char empty[PBAR_LEN] = "                                        ";

//config file parser constants
#define TOKEN_HOSTS    "[hosts]"
#define TOKEN_USERNAME "[username]"
#define TOKEN_CMD      "[cmd]"
#define TOKEN_RELPATH  "[path]"
#define TOKEN_ARGS     "[args]"
#define TOKEN_COMMENT  "//"


typedef struct host {
    char addr[MAX_ADDR_LEN];
    ssh_session session;
    ssh_channel channel;
    bool is_usable;
    bool is_busy;
    int pos;
} host;

static struct {
    int  n_args;
    int  n_processed;
    char args[HOST_CAPACITY][MAX_ARG_LEN];
} process_queue;

static struct {
    int  longest_addr;
    int  n_hosts;

    char username[MAX_USERNAME_LEN];
    char relpath [MAX_PATH_LEN];
    char cmd     [MAX_CMD_LEN];
    host pool    [HOST_CAPACITY];
} config;


int init_config_from_file(const char *filename)
{

    FILE *fp;
    fp = fopen(filename, "r");

    if (!fp)
    {
        perror("error opening file");
        return SSH_ERROR;
    }

    size_t line_len = 0;
    char *line_ptr = NULL;

    process_queue.n_args = 0;
    process_queue.n_processed = 0;

    config.longest_addr = 0;
    config.n_hosts = 0;
    memset(config.username, 0, MAX_USERNAME_LEN * sizeof(*config.username));
    memset(config.relpath,  0, MAX_PATH_LEN     * sizeof(*config.relpath));
    memset(config.pool,     0, HOST_CAPACITY    * sizeof(*config.pool));

    enum {
        NONE,
        HOSTS,
        USERNAME,
        RELPATH,
        CMD,
        ARGS,
    } parser_state;

    parser_state = NONE;
    while(getline(&line_ptr, &line_len, fp) != EOF)
    {
        char *comment_start = strstr(line_ptr, TOKEN_COMMENT);
        char *token;
        bool commented;

        token = strstr(line_ptr, TOKEN_HOSTS);
        commented = (comment_start != NULL) && (token > comment_start);
        if(token != NULL && !commented)
        {
            parser_state = HOSTS;
            continue;
        }

        token = strstr(line_ptr, TOKEN_USERNAME);
        commented = (comment_start != NULL) && (token > comment_start);
        if(token != NULL && !commented)
        {
            parser_state = USERNAME;
            continue;
        }

        token = strstr(line_ptr, TOKEN_CMD);
        commented = (comment_start != NULL) && (token > comment_start);
        if(token != NULL && !commented)
        {
            parser_state = CMD;
            continue;
        }

        token = strstr(line_ptr, TOKEN_ARGS);
        commented = (comment_start != NULL) && (token > comment_start);
        if(token != NULL && !commented)
        {
            parser_state = ARGS;
            continue;
        }

        token = strstr(line_ptr, TOKEN_RELPATH);
        commented = (comment_start != NULL) && (token > comment_start);
        if(token != NULL && !commented)
        {
            parser_state = RELPATH;
            continue;
        }

        char *ptr;
        size_t len;
        switch(parser_state)
        {
            case NONE:
                break;
            case HOSTS:
                if (comment_start != NULL) *comment_start = ' ';
                ptr = strtok(line_ptr, " \n");
                if (ptr == NULL) break;
                len = strlen(ptr);
                if (len > MAX_ADDR_LEN) 
                {
                    fprintf(stderr, "parse error: encountered address that exceeds maximum length:\naddress:%s\nmaxlen:%d\n",
                            ptr, 
                            MAX_ADDR_LEN);
                    fclose(fp);
                    return SSH_ERROR;
                }
                if ((int)len > config.longest_addr) config.longest_addr = (int) len;
                strcpy(config.pool[config.n_hosts].addr, ptr);
                config.pool[config.n_hosts].pos = config.n_hosts;
                config.n_hosts++;
                break;
            case USERNAME:
                if (comment_start != NULL) *comment_start = ' ';
                ptr = strtok(line_ptr, " \n");
                if (ptr == NULL) break;
                len = strlen(ptr);
                if (len > MAX_USERNAME_LEN) 
                {
                    fprintf(stderr, "parse error: encountered username that exceeds maximum length:\nusername:%s\nmaxlen:%d\n",
                            ptr, 
                            MAX_USERNAME_LEN);
                    fclose(fp);
                    return SSH_ERROR;
                }
                if (*config.username)
                {
                    fprintf(stderr, "parse error: multiple usernames given\n");
                    fclose(fp);
                    return SSH_ERROR;
                }
                strcpy(config.username, ptr);
                break;
            case CMD:
                if (comment_start != NULL) *comment_start = ' ';
                ptr = strtok(line_ptr, " \n");
                if (ptr == NULL) break;
                len = strlen(ptr);
                if (len > MAX_CMD_LEN) 
                {
                    fprintf(stderr, "parse error: encountered command that exceeds maximum length:\ncommand:%s\nmaxlen:%d\n",
                            ptr, 
                            MAX_CMD_LEN);
                    fclose(fp);
                    return SSH_ERROR;
                }
                if (*config.cmd)
                {
                    fprintf(stderr, "parse error: multiple commands given\n");
                    fclose(fp);
                    return SSH_ERROR;
                }
                strcpy(config.cmd, ptr);
                break;
            case ARGS:
                if (comment_start != NULL) *comment_start = ' ';
                ptr = strtok(line_ptr, " \n");
                if (ptr == NULL) break;
                len = strlen(ptr);
                if (len > MAX_ARG_LEN) 
                {
                    fprintf(stderr, "parse error: encountered arg that exceeds maximum length:\narg:%s\nmaxlen:%d\n",
                            ptr, 
                            MAX_ARG_LEN);
                    fclose(fp);
                    return SSH_ERROR;
                }
                strcpy(process_queue.args[process_queue.n_args], ptr);
                process_queue.n_args++;
                break;
            case RELPATH:
                if (comment_start != NULL) *comment_start = ' ';
                ptr = strtok(line_ptr, " \n");
                if (ptr == NULL) break;
                len = strlen(ptr);
                if (len > MAX_PATH_LEN) 
                {
                    fprintf(stderr, "parse error: encountered a path that exceeds maximum length:\narg:%s\nmaxlen:%d\n",
                            ptr, 
                            MAX_PATH_LEN);
                    fclose(fp);
                    return SSH_ERROR;
                }
                strcpy(config.relpath, ptr);
                process_queue.n_args++;
                break;
        }
    }

    if (!*config.username)
    {
        fprintf(stderr, "no username supplied in config file\n");
        fclose(fp);
        return SSH_ERROR;
    }
    if (!*config.cmd) 
    {
        fprintf(stderr, "no command supplied in config file\n");
        fclose(fp);
        return SSH_ERROR;
    }

    fclose(fp);
    return SSH_OK;
}

static void host_print(host h, const char *fmt, ...)
{

    const int n = h.pos + 1;
    const char *address = h.addr;

    va_list args;
    va_start (args, fmt);

    printf(ANSI_UP, n);
    printf(ANSI_CLEAR_LINE);
    printf(ANSI_BEGIN);
    printf("%-*s ", config.longest_addr, address);
    vprintf(fmt, args); 
    printf(ANSI_DOWN, n);
    printf(ANSI_BEGIN);
    fflush(stdout);

    va_end(args);
}

int host_authenticate(host h)
{
    int auth_code;
    ssh_session session = h.session;

    host_print(h, "trying authentication method: none");
    auth_code = ssh_userauth_none(session, NULL);
    switch (auth_code)
    {
        case SSH_AUTH_SUCCESS:
            host_print(h, "authentication succeeded");
            return SSH_OK;
        case SSH_AUTH_DENIED: //fallthrough
        default:
            host_print(h, "authentication failed");
    }

    int supported_auth_methods = ssh_userauth_list(session, NULL);
    int method_pubkey   = SSH_AUTH_METHOD_PUBLICKEY  & supported_auth_methods;
    int method_password = SSH_AUTH_METHOD_PASSWORD   & supported_auth_methods;
    int method_gssapi   = SSH_AUTH_METHOD_GSSAPI_MIC & supported_auth_methods;

    if (method_gssapi)
    {
        host_print(h, "trying authentication method: gssapi");
        auth_code = ssh_userauth_gssapi(session);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                host_print(h, "authentication succeeded");
                return SSH_OK;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                host_print(h, "authentication failed");
        }
    } 
    if (method_pubkey)
    {
        host_print(h, "trying authentication method: ssh key");
        auth_code = ssh_userauth_publickey_auto(session, NULL, NULL);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                host_print(h, "authentication succeeded");
                return SSH_OK;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                host_print(h, "authentication failed");
        }
    } 
    if (method_password)
    {
        host_print(h, "trying authentication method: password");
        char *password = getpass("password: ");
        auth_code = ssh_userauth_password(session, NULL, password);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                host_print(h, "authentication succeeded");
                return SSH_OK;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                host_print(h, "authentication failed");
        }
    } 

    host_print(h, "no authentication possible");
    return SSH_ERROR;
}


int host_verify_knownhost(host h)
{

    ssh_session session = h.session;
    enum ssh_known_hosts_e state;
    ssh_key srv_pubkey = NULL;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return SSH_ERROR;
    }
 
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return SSH_ERROR;
    }
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            host_print(h, "host key for server changed. for security reasons, connection will be stopped");
            return SSH_ERROR;
        case SSH_KNOWN_HOSTS_OTHER:
            host_print(h, "The host key for this server was not found but an other"
                    "type of key exists.");
            return SSH_ERROR;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            host_print(h, "Could not find known host file.");
            host_print(h, "If you accept the host key here, the file will be"
                    "automatically created.");
 
            [[fallthrough]];
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            host_print(h, "The server is unknown. Trusting without asking.");
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                return SSH_ERROR;
            }
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            host_print(h, "Error %s", ssh_get_error(session));
            return SSH_ERROR;
    }
    return SSH_OK;
}

void host_connect(host *h_ptr)
{
    int rc;
    const long timeout = 2;
    const char *addr = h_ptr->addr;
    ssh_session session = ssh_new();
    h_ptr->session = session;

    if (session == NULL)
    {
        host_print(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, (void *)addr);
    if (rc < 0)
    {
        host_print(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_USER, (void *)config.username);
    if (rc < 0)
    {
        host_print(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_TIMEOUT, (void *)&timeout);
    if (rc < 0)
    {
        host_print(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        host_print(*h_ptr, "unable to connect");
        return;
    }

    rc = host_authenticate(*h_ptr);
    if (rc != SSH_OK) {
        host_print(*h_ptr, "unable to authenticate host");
        return;
    }

    rc = host_verify_knownhost(*h_ptr);
    if (rc != SSH_OK) {
        host_print(*h_ptr, "unable to verify host");
        return;
    }

    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL)
    {
        host_print(*h_ptr, "error: could not create ssh channel.");
        return;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        host_print(*h_ptr, "unable to open session");
        return;
    }

    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK) {
        host_print(*h_ptr, "unable to request shell");
        return;
    }

    h_ptr->channel = channel;
    h_ptr->is_usable = true;
    return;
}

void unregister_all_hosts()
{
    int n_hosts = config.n_hosts;
    for (int i = 0; i < n_hosts; i++)
    {
        ssh_channel channel = config.pool[i].channel;
        ssh_session session = config.pool[i].session;

        if (channel != NULL)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
        }
        if (session != NULL)
        {
            ssh_disconnect(session);
            ssh_free(session);
        }
    }
}

void host_exec(host h, const char *args)
{
    int rc;
    ssh_channel channel = h.channel;

    if (*config.relpath)
    {
        char cd_cmd_buffer[MAX_PATH_LEN + 3] = "cd ";
        strcat(cd_cmd_buffer, config.relpath);
        host_print(h, "executing command %s", cd_cmd_buffer);
        rc = ssh_channel_write(channel, cd_cmd_buffer, sizeof(cd_cmd_buffer));
        if (rc != SSH_OK)
        {
            host_print(h, "command failed");
            return;
        }
    }

    char cmd_buffer[MAX_CMD_LEN + MAX_ARG_LEN] = {0};
    strcpy(cmd_buffer, config.cmd);
    strcat(cmd_buffer, args);

    host_print(h, "executing command %s", args);
    rc = ssh_channel_write(channel, cmd_buffer, sizeof(cmd_buffer));
    if (rc != SSH_OK)
    {
        host_print(h, "command failed");
    }

}

float host_get_progress (host h)
{
    int   rc;
    int   num, denom;
    char  buffer[1024] = {0};
    char *token_start = &buffer[1023];
    char *token_end;

    ssh_channel channel = h.channel;
    rc = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
    if (rc != SSH_OK) return -1;

    while (*token_start != PROGRESS_END && token_start > &buffer[0]) token_start--;
    if    (token_start == &buffer[0]) return -1;
    token_start--;
    token_end = token_start;
    while (*token_end != PROGRESS_START && token_end > &buffer[0]) token_end++;
    if    (token_end == &buffer[0])   return -1;
    *token_start = '\0';

    if(sscanf(token_end, "%d/%d", &num, &denom) == 0 || denom == 0)
    {
        return -1;
    }
    return (float) num / denom;
}

void host_print_progress(host h, float progress)
{
    if (progress == -1)
    {
        host_print(h, "[ERROR]"); 
        return;
    }
    if   (progress > 1.00) progress = 1.00;
    if   (progress < 0.00) progress = 0.00;
    int fill = (float)progress*PBAR_LEN;
    host_print(h, "[%.*s%.*s] %0.3f%%", fill, pbar, PBAR_LEN - fill, empty, progress * 100);
}

void distribute()
{
    int n_hosts = config.n_hosts;
    for (int i = 0; i < n_hosts; i++)
    {
        printf("\n");
    }

    for (int i = n_hosts - 1; i >= 0; i--) 
        host_connect(&config.pool[i]);

    bool done = false;
    while (!done)
    {
        done = true;
        for (int i = n_hosts - 1; i >= 0; i--)
        {
            host h = config.pool[i];

            if (!h.is_usable) continue;
            if (!h.is_busy && (process_queue.n_processed < process_queue.n_args))
            {
                host_exec(h, process_queue.args[process_queue.n_processed]);
                process_queue.n_processed++;
            }

            float progress = host_get_progress(h);
            host_print_progress(h, progress);
            int rc = ssh_channel_get_exit_status(h.channel);
            if (rc != -1) h.is_busy = false;

            if (h.is_busy)
            {
                done = false;
            }
        }
    }
    unregister_all_hosts();
}
