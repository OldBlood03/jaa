#include <libssh/libssh.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "client.c"
#include "host.c"

#define SHIFT() (assert(argc > 0), argc--, *(argv++))

const char *hosts[] = {
    "smith.org.aalto.fi", 
    "befunge",
    "bit",
    "bogo",
    "brainfuck",
    "deadfish",
    "emo",
    "entropy",
    "false",
    "fractran",
    "fugue",
    "glass",
    "haifu",
    "headache",
    "intercal",
    "malbolge",
    "numberwang",
    "ook",
    "piet",
    "regexpl",
    "remorse",
    "rename",
    "shakespeare",
    "smith",
    "smurf",
    "spaghetti",
    "thue",
    "unlambda",
    "wake",
    "whenever",
    "whitespace",
    "zombie",
};

const char username[] = "longhuo1";

int main(int argc, char *argv[])
{
    char *arg = SHIFT();
    arg = SHIFT();

    printf("arguments used: %s\n", arg);
    if (strcmp(arg, "-c") == 0)
    {
        ssh_session session = connect_to_host(username, host);
        ssh_channel channel = open_channel(session);
        read_channel(channel);
        ssh_disconnect(session);
        ssh_free(session);
    }
    else if (strcmp(arg, "-h") == 0)
    {
        read_port(5000);
    }
    return 0;
}
