#include "distribute.c"
#include<unistd.h>
#include<errno.h>
#include<getopt.h>
#include<dirent.h>
#include<assert.h>
#define SHIFT() (assert(argc > 0), argc--, *(argv++))

//for config file
#define FILE_SUFFIX     ".jaa"

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

    distribute();
    return 0;
}
