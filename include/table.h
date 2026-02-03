#ifndef TABLE
#define TABLE
#include <stdarg.h>

#ifdef  NO_ANSI

#define ANSI_CLEAR_LINE ""
#define ANSI_UP         ""
#define ANSI_DOWN       ""
#define ANSI_BEGIN      ""
#define ANSI_BLINK_ON   ""
#define ANSI_BLINK_OFF  ""
#define ANSI_RED        ""
#define ANSI_WHITE      ""
#define ANSI_BLUE       ""

#else

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

#endif


typedef struct {
    int  width;
    int  v_padding;
    int  h_padding;
    char v_sep;
    char h_sep;
    char heading_sep;
} table_style;

void table_init(table_style style, int n_slates, int n_entries_per_slate);
void table_slate_printf(int slate_index, int entry_index, const char *fmt, ...);
void table_slate_vprintf(int slate_index, int entry_index, const char *fmt, va_list args);
void table_slate_clear(int slate_index, int entry_index);
void table_clear();
void table_flush();

#endif//TABLE
