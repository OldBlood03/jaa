#include "jaa.h"
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#define SHIFT() (assert(argc > 0), argc--, *(argv++))

static char help[] =
    "--file or -f <arg>"
    "\n"
    "\tassigns file <arg> as the config file containing the information on how the cmd"
    "is to be distributed"
    "\n"
    "-h"
    "\n"
    "\tprint help information"
    "\n";



int main(int argc, char *argv[])
{

    extern char *optarg;
    const struct option options[] = {
        {.name = "file", .has_arg = 1, .flag = 0, .val = 'f'},
        {.name = "help", .has_arg = 0, .flag = 0, .val = 'h'},
    };

    int  rc;
    bool got_option = false;
    while(1)
    {
        rc = getopt_long(argc, argv, "hf:", options, NULL);
        if (rc == -1) break;
        switch(rc)
        {
            case 'f':
                rc = init_config_from_file(optarg);
                got_option = true;
                break;
            case 'h':
                printf("%s", help);
                got_option = true;
                return 0;
        }
    }

    if (!got_option)
    {
        char filename[MAX_PATH_LEN];
        if (!find_config_file(filename, MAX_PATH_LEN))
        {
            fprintf(stderr, "did not find config file in current directory\n");
            return -1;
        }
        rc = init_config_from_file(filename);
    }
    if (rc != SSH_OK) return -1;

    table_style style = {
    .width = 300,
    .v_padding = 0,
    .h_padding = 10,
    .v_sep = '|',
    .h_sep = '#',
    .heading_sep = '.',
    };

    distribute(style);
    //table_init(style, 4, 4);
    //table_slate_printf(0,0, "hello");
    //table_flush();
    //sleep(1);
    //table_slate_printf(0,0, "goodbye");
    //table_slate_clear(0,0);
    //table_slate_printf(0,0, "goodbye");
    //table_clear();
    //table_flush();

    return 0;
}
