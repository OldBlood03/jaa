#include<stdio.h>
#include<libssh/libssh.h>
#include<libssh/callbacks.h>
#include<assert.h>
#include<errno.h>
#include<stdarg.h>
#include<stdbool.h>
#include<string.h>

#define ANSI_CLEAR_LINE "\033[K"
#define ANSI_UP         "\033[%dA"
#define ANSI_DOWN       "\033[%dB"
#define ANSI_BEGIN      "\r"
#define ANSI_BLINK_ON   "\033[5m"
#define ANSI_BLINK_OFF  "\033[0m"
#define ANSI_RED        "\033[38;5;9m"
#define ANSI_WHITE      "\033[38;5;15m"
#define ANSI_BLUE       "\033[38;5;12m"

#define MAX(x,y) ((x)>(y) ? (x) : (y))
#define HOST_CAPACITY    128
#define MAX_ADDR_LEN     128
#define MAX_USERNAME_LEN 128
#define MAX_PATH_LEN     128
#define MAX_CMD_LEN      128
#define MAX_ARG_LEN      128
#define STDOUT_CAPACITY  1024

//stdout progress parsing constants
//change these if u want, make sure they are not equal to each other
#define PROGRESS_START '['
#define PROGRESS_END   ']'
#if PROGRESS_START == PROGRESS_END
    #error PROGRESS_START should != PROGRESS_END but does
#endif

//progress bar
#define PBAR_LEN 41
const char pbar [PBAR_LEN] = "########################################";
const char empty[PBAR_LEN] = "                                        ";

//config file parser constants
#define TOKEN_HOSTS    "[hosts]"
#define TOKEN_USERNAME "[username]"
#define TOKEN_CMD      "[cmd]"
#define TOKEN_RELPATH  "[path]"
#define TOKEN_ARGS     "[args]"
#define TOKEN_COMMENT  "//"
#define TOKEN_LOGFILE  "[logfile]"


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

    int line_count = 0;
    size_t line_len = 0;
    char *line_ptr = NULL;

    process_queue.n_args = 0;
    process_queue.n_processed = 0;
    for (int i = 0; i < HOST_CAPACITY; i++)
    {
        memset(process_queue.args[i], 0, sizeof(process_queue.args[i]));
    }

    config.longest_addr = 0;
    config.n_hosts  = 0;
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
        LOGFILE
    } parser_state;

    parser_state = NONE;
    while(getline(&line_ptr, &line_len, fp) != EOF)
    {
        char *comment_start = strstr(line_ptr, TOKEN_COMMENT);
        char *token;
        bool commented;

        line_count ++;

        token = strstr(line_ptr, TOKEN_HOSTS);
        commented = (comment_start != NULL) && (token > comment_start);
        if(token != NULL && !commented) { parser_state = HOSTS; continue; }

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

        token = strstr(line_ptr, TOKEN_LOGFILE);
        commented = (comment_start != NULL) && (token > comment_start);
        if(token != NULL && !commented) 
        { 
            parser_state = LOGFILE;
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
                    return SSH_ERROR;
                }
                if ((int)trimmed_len > config.longest_addr) config.longest_addr = (int) trimmed_len;

                host *h = &config.pool[config.n_hosts];
                strcpy(h->addr, ptr);
                memset(h->exit_codes, 0, MAX_ADDR_LEN * sizeof(*h->exit_codes));
                h->n_exits = 0;
                h->pos = config.n_hosts;
                h->is_busy = false;
                h->is_usable = false;
                config.n_hosts++;
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
                    return SSH_ERROR;
                }
                if (*config.username)
                {
                    fprintf(stderr, "parse error on line %d: multiple usernames given\n", line_count);
                    fclose(fp);
                    return SSH_ERROR;
                }
                strcpy(config.username, ptr);
                break;
            case CMD:
                trimmed_len = strlen(ptr) + 1;
                if (trimmed_len > MAX_CMD_LEN) 
                {
                    fprintf(stderr, "parse error on line %d: encountered command that exceeds maximum length:\ncommand:%s\nmaxlen:%d\n",
                            line_count,
                            ptr, 
                            MAX_CMD_LEN);
                    fclose(fp);
                    return SSH_ERROR;
                }
                if (*config.cmd)
                {
                    fprintf(stderr, "parse error on line %d: multiple commands given\n", line_count);
                    fclose(fp);
                    return SSH_ERROR;
                }
                strcpy(config.cmd, ptr);
                break;
            case ARGS:
                trimmed_len = strlen(ptr) + 1;
                if (trimmed_len > MAX_ARG_LEN) 
                {
                    fprintf(stderr,
                            "parse error on line %d: encountered arg that exceeds maximum length:\narg:%s\nmaxlen:%d\n",
                            line_count,
                            ptr, 
                            MAX_ARG_LEN);
                    fclose(fp);
                    return SSH_ERROR;
                }
                strcpy(process_queue.args[process_queue.n_args], ptr);
                process_queue.n_args++;
                break;
            case RELPATH:
                if (trimmed_len > MAX_PATH_LEN) 
                {
                    fprintf(stderr,
                            "parse error on line %d: encountered a path that exceeds maximum length:\narg:%s\nmaxlen:%d\n",
                            line_count,
                            ptr, 
                            MAX_PATH_LEN);
                    fclose(fp);
                    return SSH_ERROR;
                }
                strcpy(config.relpath, ptr);
                break;
            case LOGFILE:
                if (trimmed_len > MAX_PATH_LEN) 
                {
                    fprintf(stderr,
                            "parse error: encountered a path that exceeds maximum length:\narg:%s\nmaxlen:%d\n",
                            ptr, 
                            MAX_PATH_LEN);
                    fclose(fp);
                    return SSH_ERROR;
                }
                strcpy(config.relpath, ptr);
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
    if (process_queue.n_args == 0)  process_queue.n_args = config.n_hosts;

    fclose(fp);
    return SSH_OK;
}

static void host_printf(host h, const char *fmt, ...)
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

static void host_clearline(host h)
{
    const int n = h.pos + 1;
    printf(ANSI_UP, n);
    printf(ANSI_CLEAR_LINE);
    printf(ANSI_BEGIN);
    printf(ANSI_DOWN, n);
}

static void host_cumulative_printf(host h, const char *fmt, ...)
{
    const int n = h.pos + 1;

    va_list args;
    va_start (args, fmt);

    printf(ANSI_UP, n);
    vprintf(fmt, args); 
    printf(ANSI_DOWN, n);
    fflush(stdout);

    va_end(args);
}

int host_authenticate(host h)
{
    int auth_code;
    ssh_session session = h.session;

    host_printf(h, "trying authentication method: none");
    auth_code = ssh_userauth_none(session, NULL);
    switch (auth_code)
    {
        case SSH_AUTH_SUCCESS:
            host_printf(h, "authentication succeeded");
            return SSH_OK;
        case SSH_AUTH_DENIED: //fallthrough
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
                return SSH_OK;
            case SSH_AUTH_DENIED: //fallthrough
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
                return SSH_OK;
            case SSH_AUTH_DENIED: //fallthrough
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
                return SSH_OK;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                host_printf(h, "authentication failed");
        }
    } 

    host_printf(h, "no authentication possible");
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

void host_new(host *h_ptr)
{
    int rc;
    const long timeout = 2;
    const char *addr = h_ptr->addr;
    ssh_session session = ssh_new();
    h_ptr->session = session;

    if (session == NULL)
    {
        host_printf(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, (void *)addr);
    if (rc < 0)
    {
        host_printf(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_USER, (void *)config.username);
    if (rc < 0)
    {
        host_printf(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_TIMEOUT, (void *)&timeout);
    if (rc < 0)
    {
        host_printf(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        host_printf(*h_ptr, "unable to connect");
        return;
    }

    rc = host_authenticate(*h_ptr);
    if (rc != SSH_OK) {
        host_printf(*h_ptr, "unable to authenticate host");
        return;
    }

    rc = host_verify_knownhost(*h_ptr);
    if (rc != SSH_OK) {
        host_printf(*h_ptr, "unable to verify host");
        return;
    }

    h_ptr->is_usable = true;
    return;
}

void host_free(host h)
{
    ssh_channel_close(h.channel);
    ssh_channel_free(h.channel);
    ssh_disconnect(h.session);
    ssh_free(h.session);
}

void host_exec(host *h, const char *args)
{
    int rc;
    ssh_channel channel = ssh_channel_new(h->session);
    if (channel == NULL)
    {
        host_printf(*h, "error: could not create ssh channel.");
        return;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        host_printf(*h, "unable to open session");
        return;
    }

    h->channel = channel;

    char cmd_buffer[3 + MAX_PATH_LEN + 1 + MAX_CMD_LEN + MAX_ARG_LEN + 1] = {0};
    if (*config.relpath)
    {
        strcat(cmd_buffer, "cd ");
        strcat(cmd_buffer, config.relpath);
        strcat(cmd_buffer, ";");
    }

    strcat(cmd_buffer, config.cmd);
    strcat(cmd_buffer, " ");
    strcat(cmd_buffer, args);

    host_printf(*h, "executing command %s", cmd_buffer);
    rc = ssh_channel_request_exec(channel, cmd_buffer);
    if (rc == SSH_ERROR)
    {
        host_printf(*h, "command failed");
    }

}

void host_read(host *h)
{
    int rc;
    ssh_channel channel = h->channel;
    if (!ssh_channel_is_open(channel)) return;

    rc = ssh_channel_read(channel, h->stdout_buffer, sizeof(h->stdout_buffer) - 1, 0);
    if (rc == SSH_ERROR) return;

    rc = ssh_channel_read(channel, h->stderr_buffer, sizeof(h->stderr_buffer) - 1, 1);
    if (rc == SSH_ERROR) return;
    return;
}

void host_cumulative_print_stderr(host h)
{
    for (char *ptr = h.stderr_buffer; *ptr != '\0'; ptr++)
    {
        if (*ptr == '\n') 
            *ptr = ' ';
    }
    host_cumulative_printf(h, ANSI_RED "%s" ANSI_WHITE, h.stderr_buffer);
}
void host_cumulative_print_progress(host h)
{
    int   num, denom;
    char *stdout_buffer = h.stdout_buffer;
    char *token_end = &stdout_buffer[STDOUT_CAPACITY - 1];
    char *token_start;

    while (*token_end != PROGRESS_END && token_end > &stdout_buffer[0]) token_end--;
    if    (token_end == &stdout_buffer[0] && *token_end != PROGRESS_END) 
    {
        host_cumulative_print_stderr(h);
        return;
    }
    token_end--;
    token_start = token_end;
    while (*token_start != PROGRESS_START && token_start > &stdout_buffer[0]) token_start--;
    if    (token_start == &stdout_buffer[0] && *token_start != PROGRESS_START) 
    {
        host_cumulative_print_stderr(h);
        return;
    }
    token_end ++;
    *token_end = '\0';
    token_start++;

    if(sscanf(token_start, "%d/%d", &num, &denom) == 0 || denom == 0)
    {
        host_cumulative_print_stderr(h);
        return;
    }

    float progress = (float) num / denom;
    if (progress > 1.00) progress = 1.00;
    if (progress < 0.00) progress = 0.00;
    const int fill = (float)progress*PBAR_LEN;
    const int remaining = PBAR_LEN - fill;
    host_cumulative_printf(h, "[%.*s%.*s] %d/%d", fill, pbar, remaining, empty, num, denom);
}

void host_cumulative_print_processes(host h)
{
    host_cumulative_printf(h, "[");
    for (int i = 0; i < h.n_exits; i++)
    {
        if (h.exit_codes[i] != 0)
        {
            host_cumulative_printf(h, ANSI_RED "*" ANSI_WHITE);
        }
        else
        {
            host_cumulative_printf(h, ANSI_BLUE "*" ANSI_WHITE);
        }
    }
    if (h.is_busy)
    {
        host_cumulative_printf(h, ANSI_BLINK_ON "*" ANSI_BLINK_OFF "] ");
    }
    else
    {
        host_cumulative_printf(h, "]" );
    }
   
}

void remove_unusable_hosts()
{
    for (int i = 0; i < config.n_hosts; i++)
    {
        if (!config.pool[i].is_usable)
        {
            host_free(config.pool[i]);
            config.n_hosts--;
            for (int j = i; j < config.n_hosts - 1; j++)
            {
                config.pool[j] = config.pool[j+1];
                config.pool[j].pos--;
            }
        }
    }
}

void clear_screen()
{
    for (int i = 0; i < config.n_hosts; i++)
    {
        printf(ANSI_UP, 1);
        printf(ANSI_CLEAR_LINE);
    }
    printf(ANSI_DOWN, config.n_hosts);
}

void pad_screen()
{
    for (int i = 0; i < config.n_hosts; i++)
        printf("\n");
}

void distribute()
{
    int n_hosts = config.n_hosts;
    pad_screen();

    for (int i = n_hosts - 1; i >= 0; i--) 
        host_new(&config.pool[i]);

    clear_screen();
    remove_unusable_hosts();

    bool done = false;
    while (!done)
    {
        done = true;
        for (int i = n_hosts - 1; i >= 0; i--)
        {
            host *h = &config.pool[i];

            if (!h->is_usable) continue;
            if (!h->is_busy && (process_queue.n_processed < process_queue.n_args))
            {
                host_exec(h, process_queue.args[process_queue.n_processed]);
                h->is_busy = true;
                process_queue.n_processed++;
            }

            if (h->is_busy) 
            {
                done = false;
            }

            if (h->is_busy && !ssh_channel_is_open(h->channel))
            {
                int exit_code = ssh_channel_get_exit_status(h->channel);
                h->is_busy = false;
                h->exit_codes[h->n_exits] = exit_code;
                h->n_exits ++;
            }

            host_clearline(*h);
            host_read(h);
            host_cumulative_print_processes(*h);
            host_cumulative_printf(*h, "%-*s ",config.longest_addr, h->addr);
            host_cumulative_print_progress(*h);

        }
    }
    for (int i = n_hosts; i < n_hosts; i++)
    {
        host_free(config.pool[i]);
    }
}
