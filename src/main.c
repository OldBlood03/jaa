#include "distribute.c"
#include<unistd.h>
#include<getopt.h>
#include<assert.h>
#define SHIFT() (argc--, *(argv++))

const char *host_names[] = {
};

void print_help()
{
    printf(
    "--file <arg>\n"
    "\tassigns file <arg> as the file containing the list of host SSH addresses\n"
    "\tfile must have each address separated by a new-line\n"
    "--usr <arg>\n"
    "\tassigns <arg> as the login user for all hosts"
    "--cmd <arg>\n"
    "\tassigns <arg> as the cmd to be executed on all hosts"
    "-h\n"
    "\tprint help information\n"
    );
}

int main(int argc, char *argv[])
{
    bool has_filename = false;
    bool has_username = false;
    bool has_cmd = false;

    extern char *optarg;
    const struct option options[] = {
        {.name = "file", .has_arg = 1, .flag = 0, .val = 'f'},
        {.name = "usr" , .has_arg = 1, .flag = 0, .val = 'u'},
        {.name = "cmd" , .has_arg = 1, .flag = 0, .val = 'c'},
        {.name = "help", .has_arg = 0, .flag = 0, .val = 'h'},
    };

    while(1)
    {
        int rc = getopt_long(argc, argv, "h:f", options, NULL);
        if (rc == -1) break;

        switch (rc)
        {
            case 'f':
                init_hosts_from_file(optarg);
                has_filename = true;
                break;
            case 'u':
                init_username(optarg);
                has_username = true;
                break;
            case 'c':
                init_cmd(optarg);
                has_cmd = true;
                break;
            case 'h':
                print_help();
                return 0;
            default:
                break;
        }
    }

    if (!has_username)
    {
        fprintf(stderr, "no username to be distributed. did you forget to use --usr <arg>?");
        return -1;
    }
    if (!has_filename)
    {
        fprintf(stderr, "no filename provided. did you forget to use --file <arg>?");
        return -1;
    }
    if (!has_cmd)
    {
        fprintf(stderr, "no command to be distributed. did you forget to use --cmd <arg>?");
        return -1;
    }

    distribute();
    unregister_all_hosts();
    return 0;
}
