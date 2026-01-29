#include<stdio.h>
#include<libssh/libssh.h>
#include<errno.h>
#include<stdarg.h>
#include<stdbool.h>
#include<string.h>

#define ANSI_CLEAR_LINE "\033[K"
#define ANSI_UP "\033[%dA"
#define ANSI_DOWN "\033[%dB"
#define ANSI_BEGIN "\r"

#define HOST_CAPACITY 128
#define MAX_ADDR_LEN 128
#define MAX_USERNAME_LEN 128
#define MAX_CMD_LEN 1024


typedef struct host {
    char addr[MAX_ADDR_LEN];
    ssh_session session;
    ssh_channel channel;
    bool is_usable;
    bool is_finished;
    int pos;
} host;

static struct {
    int size;
    host pool[HOST_CAPACITY];
} hosts;

static int  longest_addr = 0;
static char username[MAX_USERNAME_LEN];
static char cmd[MAX_CMD_LEN];

void init_cmd(const char *c)
{
    strcpy(cmd, c);
}

void init_username(const char *usr)
{
    strcpy(username, usr);
}

int init_hosts_from_file(const char *filename)
{
    FILE *fp;
    fp = fopen(filename, "r");

    if (!fp)
    {
        perror("error opening file");
        return SSH_ERROR;
    }
    char buffer[MAX_ADDR_LEN];
    for (int i = 0; fgets(buffer, MAX_ADDR_LEN, fp) != NULL; i++)
    {
        if (ferror(fp))
        {
            perror("error reading file contents");
            fclose(fp);
            return SSH_ERROR;
        }

        if (strchr(buffer, '\n') == NULL)
        {
            fprintf(stderr, "address length exceeds hard-coded 128 byte limit");
            fclose(fp);
            return SSH_ERROR;
        }

        strtok(buffer, "\n");
        strcpy(hosts.pool[i].addr, buffer);
        int addr_len = strlen(buffer);
        if (longest_addr < addr_len)
            longest_addr = addr_len;

        if (hosts.size == HOST_CAPACITY)
        {
            fprintf(stderr, "host capacity reached, update the HOST_CAPACITY value in source code for more");
            fclose(fp);
            return SSH_ERROR;
        }
        hosts.pool[i].pos = hosts.size;
        hosts.size ++;
    }

    for (int i = 0; i < hosts.size; i++)
    {
        printf("\n");
    }

    fclose(fp);
    return SSH_OK;
}

void print_host(host h, const char *fmt, ...)
{

    const int n = h.pos + 1;
    const char *address = h.addr;

    va_list args;
    va_start (args, fmt);

    printf(ANSI_UP, n);
    printf(ANSI_CLEAR_LINE);
    printf(ANSI_BEGIN);
    printf("%-*s ", longest_addr, address);
    vprintf(fmt, args); 
    fflush(stdout);
    printf(ANSI_DOWN, n);
    printf(ANSI_BEGIN);

    va_end(args);
}

int authenticate(host h)
{
    int auth_code;
    ssh_session session = h.session;

    print_host(h, "trying authentication method: none");
    auth_code = ssh_userauth_none(session, NULL);
    switch (auth_code)
    {
        case SSH_AUTH_SUCCESS:
            print_host(h, "authentication succeeded");
            return SSH_OK;
        case SSH_AUTH_DENIED: //fallthrough
        default:
            print_host(h, "authentication failed");
    }

    int supported_auth_methods = ssh_userauth_list(session, NULL);
    int method_pubkey   = SSH_AUTH_METHOD_PUBLICKEY  & supported_auth_methods;
    int method_password = SSH_AUTH_METHOD_PASSWORD   & supported_auth_methods;
    int method_gssapi   = SSH_AUTH_METHOD_GSSAPI_MIC & supported_auth_methods;

    if (method_gssapi)
    {
        print_host(h, "trying authentication method: gssapi");
        auth_code = ssh_userauth_gssapi(session);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                print_host(h, "authentication succeeded");
                return SSH_OK;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                print_host(h, "authentication failed");
        }
    } 
    if (method_pubkey)
    {
        print_host(h, "trying authentication method: ssh key");
        auth_code = ssh_userauth_publickey_auto(session, NULL, NULL);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                print_host(h, "authentication succeeded");
                return SSH_OK;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                print_host(h, "authentication failed");
        }
    } 
    if (method_password)
    {
        print_host(h, "trying authentication method: password");
        char *password = getpass("password: ");
        auth_code = ssh_userauth_password(session, NULL, password);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                print_host(h, "authentication succeeded");
                return SSH_OK;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                print_host(h, "authentication failed");
        }
    } 

    print_host(h, "no authentication possible");
    return SSH_ERROR;
}


int verify_knownhost(host h)
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
            print_host(h, "host key for server changed. for security reasons, connection will be stopped");
            return SSH_ERROR;
        case SSH_KNOWN_HOSTS_OTHER:
            print_host(h, "The host key for this server was not found but an other"
                    "type of key exists.");
            return SSH_ERROR;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            print_host(h, "Could not find known host file.");
            print_host(h, "If you accept the host key here, the file will be"
                    "automatically created.");
 
            [[fallthrough]];
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            print_host(h, "The server is unknown. Trusting without asking.");
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                return SSH_ERROR;
            }
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            print_host(h, "Error %s", ssh_get_error(session));
            return SSH_ERROR;
    }
 
    return SSH_OK;
}

void connect_host(host *h_ptr)
{
    int rc;
    const long timeout = 2;
    const char *addr = h_ptr->addr;
    ssh_session session = ssh_new();
    h_ptr->session = session;

    if (session == NULL)
    {
        print_host(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, (void *)addr);
    if (rc < 0)
    {
        print_host(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_USER, (void *)username);
    if (rc < 0)
    {
        print_host(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_TIMEOUT, (void *)&timeout);
    if (rc < 0)
    {
        print_host(*h_ptr, "error: %s", ssh_get_error(session));
        return;
    }

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        print_host(*h_ptr, "unable to connect");
        return;
    }

    if (rc != SSH_OK) {
        print_host(*h_ptr, "unable to authenticate");
        return;
    }
    rc = authenticate(*h_ptr);
    if (rc != SSH_OK) {
        print_host(*h_ptr, "unable to authenticate");
        return;
    }

    rc = verify_knownhost(*h_ptr);
    if (rc != SSH_OK) {
        print_host(*h_ptr, "unable to verify host");
        return;
    }

    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL)
    {
        print_host(*h_ptr, "error: could not create ssh channel.");
        return;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        print_host(*h_ptr, "unable to open session");
        return;
    }

    h_ptr->channel = channel;
    h_ptr->is_usable = true;
    return;
}

void unregister_all_hosts()
{
    int n_hosts = hosts.size;
    for (int i = 0; i < n_hosts; i++)
    {
        ssh_channel channel = hosts.pool[i].channel;
        ssh_session session = hosts.pool[i].session;

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

void exec_command(host h, char *cmd)
{
    int err;
    ssh_channel channel = h.channel;

    print_host(h, "executing command...");
    err = ssh_channel_request_exec(channel, cmd);
    if (err != SSH_OK)
    {
        print_host(h, "command failed");
    }
}

static char *custom_strtok (char *str, const char *delims)
{
    static char *end_ptr;
    if (str != NULL)
    {
        end_ptr = str;
    }
    char *start_ptr = end_ptr;
    for (;*end_ptr != '\0'; end_ptr++)
    {
        for (const char *delim_ptr = delims; *delim_ptr != '\0'; delim_ptr++)
        {
            if (*end_ptr == *delim_ptr)
            {
                *end_ptr = '\0';
                end_ptr ++;
                return start_ptr;
            }
        }
    }
    return NULL;
}

void print_progress(host h)
{
    ssh_channel channel = h.channel;
    char buffer[1024] = {0};
    ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);

    char *ptr = custom_strtok(buffer, "@");
    ptr = custom_strtok(NULL, "@");
    if (ptr == NULL) return;
    int n1, n2;

    if(sscanf(ptr, "%d/%d", &n1, &n2) == 0 || n2 == 0)
    {
        print_host(h, "[ERROR] 0.00%%");
        fflush(stdout);
        return;
    }

    const int total = 20;
    char pbar[20] = "####################";
    char empty[20] = "                    ";
    float progress = (float) n1 / n2;
    if (progress > 1.00) 
    {
        progress = 1.00;
    }
    if (progress < 0.00) 
    {
        progress = 0.00;
    }
    int fill = (float)progress*total;

    print_host(h, "[%.*s%.*s] %.2f%%", fill, pbar, total - fill, empty, progress * 100);
    fflush(stdout);
}

void distribute()
{
    int n_hosts = hosts.size;
    for (int i = n_hosts - 1; i >= 0; i--)
    {
        connect_host(&hosts.pool[i]);
    }

    for (int i = n_hosts - 1; i >= 0; i--)
    {
        if (!hosts.pool[i].is_usable) continue;
        exec_command(hosts.pool[i], cmd);
    }

    bool done = false;
    while (!done)
    {
        done = true;
        for (int i = n_hosts - 1; i >= 0; i--)
        {
            print_progress(hosts.pool[i]);
            if (!hosts.pool[i].is_usable) 
                continue;
            if (!hosts.pool[i].is_finished)
                done = false;
        }
    }
}
