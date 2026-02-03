#include "table.h"
#include <stdio.h>
#define ANSI_CLEAR_LINE "\033[K"
#define ANSI_UP         "\033[%dA"
#define ANSI_DOWN       "\033[%dB"
#define ANSI_BEGIN      "\r"
#define ANSI_BLINK_ON   "\033[5m"
#define ANSI_BLINK_OFF  "\033[0m"
#define ANSI_RED        "\033[38;5;9m"
#define ANSI_WHITE      "\033[38;5;15m"
#define ANSI_BLUE       "\033[38;5;12m"
#define ANSI_RIGHT      "\033[%dC"
int main(void)
{

    table_init(style, 5, 3);
    table_slate_printf(0,0, ANSI_RED ANSI_BLINK_ON "hello worlsdasdasdsadddddddddddddddddddddddddddddddddddfhasoidjojgidfrjgoiejdoiwjdoiawjdoijsguhoidjaijdoiajfifdfiopadkjic" ANSI_BLINK_OFF ANSI_WHITE);
    table_slate_clear(0,0);
    table_flush();
    return 0;
}
