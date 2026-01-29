#include<stdarg.h>
#include<stdbool.h>
#include<stdio.h>
#include<unistd.h>

#define CLEAR_LINE "\033[K"
#define UP "\033[%dA"
#define DOWN "\033[%dB"
#define BEGIN "\r"

typedef struct host {
    const char *addr;
    int pos;
} host;

void print_host(host h, const char *fmt, ...)
{

    const int n = h.pos + 1;
    const char *address = h.addr;

    va_list args;
    va_start (args, fmt);

    printf(UP, n);
    printf(CLEAR_LINE);
    printf(BEGIN);
    printf("%s: ", address);
    vprintf(fmt, args); 
    fflush(stdout);
    printf(DOWN, n);
    printf(BEGIN);

    va_end(args);
}

int main(void)
{
    host h1 = {
            .addr = "addr",
            .pos = 0,
    };
    host h2 = {
            .addr = "addr",
            .pos = 1,
    };
    printf("\n");
    printf("\n");
    for (int i = 0;;i++)
    {
        print_host(h1, "%d", i);
        print_host(h2, "%d", i);
    }
    return 0;
}
