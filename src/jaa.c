#include "jaa.h"
#include "table.h"
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <libssh/libssh.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

//config file parser constants
#define TOKEN_HOSTS    "[hosts]"
#define TOKEN_USERNAME "[username]"
#define TOKEN_CMD      "[cmd]"
#define TOKEN_RELPATH  "[path]"
#define TOKEN_ARGS     "[args]"
#define TOKEN_COMMENT  "//"
#define TOKEN_LOGFILE  "[logfile]"

#define FILE_SUFFIX ".jaa"


//stdout progress parsing constants
//change these if u want, make sure they are not equal to each other
#define PROGRESS_START '['
#define PROGRESS_END   ']'
#if PROGRESS_START == PROGRESS_END
    #error PROGRESS_START should != PROGRESS_END but does
#endif

#define PBAR_LEN 40
static char pbar [PBAR_LEN] = "########################################";
static char empty[PBAR_LEN] = "                                        ";

#define TABLE_ENTRY_HEADER    0
#define TABLE_ENTRY_PROGRESS  1 
#define TABLE_ENTRY_ERROR_MSG 2
#define TABLE_ENTRY_STDOUT    3
#define TABLE_ENTRY_STDERR    4
#define TABLE_ENTRY_N_ENTRIES 5

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

int find_config_file(char *filename_out, size_t capacity)
{
    if(getcwd(filename_out, capacity) == NULL)
    {
        perror("error getting current directory");
        return 0;
    }
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir (filename_out)) == NULL) {
        perror("error reading contents of directory");
        closedir (dir);    
        return 0;
    }

    while ((ent = readdir (dir)) != NULL) {
        size_t filename_len = strlen(ent->d_name);
        size_t suffix_len   = strlen(FILE_SUFFIX);
        if (strcmp(&ent->d_name[filename_len - suffix_len], FILE_SUFFIX) == 0)
        {
            strcpy(filename_out, ent->d_name);
            closedir(dir);
            return 1;
        }
    }
    closedir (dir);    
    return 0;
}

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
                h->id = config.n_hosts;
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
    va_list args;
    va_start(args, fmt);
    table_slate_clear(h.id, TABLE_ENTRY_ERROR_MSG);
    table_slate_vprintf(h.id, TABLE_ENTRY_ERROR_MSG, fmt, args);
    va_end(args);
}

static int host_authenticate(host h)
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


static int host_verify_knownhost(host h)
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

static void host_new(host *h_ptr)
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

static void host_free(host h)
{
    ssh_channel_close(h.channel);
    ssh_channel_free(h.channel);
    ssh_disconnect(h.session);
    ssh_free(h.session);
}

static void host_exec(host *h, const char *args)
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

void host_read_io(host *h)
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

static void host_print_io(const host *h)
{

    table_slate_clear(h->id, TABLE_ENTRY_STDOUT);
    table_slate_printf(h->id, TABLE_ENTRY_STDOUT, h->stdout_buffer);

    table_slate_clear(h->id, TABLE_ENTRY_STDERR);
    table_slate_printf(h->id, TABLE_ENTRY_STDERR, ANSI_RED);
    table_slate_printf(h->id, TABLE_ENTRY_STDERR, h->stderr_buffer);
    table_slate_printf(h->id, TABLE_ENTRY_STDERR, ANSI_WHITE);
}

static void host_parse_progress_from_io(host *h)
{
    int   num,denom;
    char buffer[STDOUT_CAPACITY] = {0};
    strcpy(buffer, h->stdout_buffer);
    char *token_end = &buffer[STDOUT_CAPACITY - 1];
    char *token_start;

    while (*token_end != PROGRESS_END && token_end > &buffer[0]) token_end--;
    if    (token_end == &buffer[0] && *token_end != PROGRESS_END) 
        return;

    token_end--;
    token_start = token_end;
    while (*token_start != PROGRESS_START && token_start > &buffer[0]) token_start--;
    if    (token_start == &buffer[0] && *token_start != PROGRESS_START) 
        return;

    token_end ++;
    *token_end = '\0';
    token_start++;

    if(sscanf(token_start, "%d/%d", &num, &denom) == 0 || denom == 0)
    {
        table_slate_clear(h->id, TABLE_ENTRY_ERROR_MSG);
        table_slate_printf(h->id, TABLE_ENTRY_ERROR_MSG, "no progress detected in stdout");
        return;
    }

    h->progress_num = num; h->progress_denom = denom;
    return;
}

static void host_print_progress(const host *h)
{
    if (h->progress_denom == 0) return;
    float progress = (float) h->progress_num / h->progress_denom;
    if (progress > 1.00) progress = 1.00;
    if (progress < 0.00) progress = 0.00;
    const int fill = (float)progress*PBAR_LEN;
    const int remaining = PBAR_LEN - fill;
    table_slate_clear(h->id, TABLE_ENTRY_PROGRESS);
    table_slate_printf(h->id, TABLE_ENTRY_PROGRESS, "[%.*s%.*s] %d/%d", fill, pbar, remaining, empty, h->progress_num, h->progress_denom);
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
                config.pool[j].id--;
            }
        }
    }
}

void distribute(table_style style)
{
    table_init(style, config.n_hosts,TABLE_ENTRY_N_ENTRIES);
    table_flush();

    for (int i = config.n_hosts - 1; i >= 0; i--) 
    {
        table_slate_printf(config.pool[i].id, TABLE_ENTRY_HEADER, config.pool[i].addr);
        host_new(&config.pool[i]);
        table_clear();
        table_flush();
    }
    table_clear();
    remove_unusable_hosts();
    table_init(style, config.n_hosts,TABLE_ENTRY_N_ENTRIES);
    table_flush();
    for (int i = config.n_hosts - 1; i >= 0; i--) 
    {
        table_slate_printf(config.pool[i].id, TABLE_ENTRY_HEADER, config.pool[i].addr);
        table_clear();
        table_flush();
    }

    bool done = false;
    while (!done)
    {
        done = true;
        for (int i = config.n_hosts - 1; i >= 0; i--)
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
                done = false;

            if (h->is_busy && !ssh_channel_is_open(h->channel))
            {
                int exit_code = ssh_channel_get_exit_status(h->channel);
                h->is_busy = false;
                h->exit_codes[h->n_exits] = exit_code;
                h->n_exits ++;
            }

            host_read_io(h);
            host_print_io(h);
            host_parse_progress_from_io(h);
            host_print_progress(h);
            table_clear();
            table_flush();
        }
    }
    for (int i = config.n_hosts; i < config.n_hosts; i++)
    {
        host_free(config.pool[i]);
    }
}
