#include "table.h"
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <asm/termbits.h>  /* Definition of TIOC*WINSZ constants */
#include <sys/ioctl.h>

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MAX_ENTRIES 10
#define MAX_TABLE_SLATES 128
#define MAX_TABLE_ROWS 512
#define MAX_ROW_LEN 1024

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
    int cursor_save_point[MAX_ENTRIES];
    int visible_capacity[MAX_ENTRIES];
    int invisible_capacity[MAX_ENTRIES];
} table_slate;

static struct {
    int n_rows;
    int n_slates;
    int n_entries;
    int entry_rows;
    int slate_rows;

    table_style style;
    char rows [MAX_TABLE_ROWS][MAX_ROW_LEN + 1];
    table_slate slates [MAX_TABLE_SLATES];
} table;

static void fill_table(char with)
{
    for (int i = 0; i < table.n_rows; i++)
    {
        for(int j = 0; j < table.style.width; j++)
        {
            table.rows[i][j] = with;
        }
    }

}

void table_init(table_style style, int n_slates, int n_entries)
{
    table.style  = style;

    struct winsize w;
    assert(ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && "something went wrong when querying terminal dimensions");

    if (style.width > w.ws_col) 
    {
        fprintf(stderr, "style specified more columns than available in the terminal. truncating.\n");
        table.style.width = w.ws_col;
    }

    assert(style.width >= 2 &&  "style width is is not wide enough to support boundary characters");
    assert(style.width <= MAX_ROW_LEN && "width greater than supported");
    assert(style.h_padding*2 <= style.width - 2 && "padding greater than the allowed width");
    assert(n_entries <= MAX_ENTRIES && "number of entries greater than the allowed limi");

    table.n_slates = n_slates;
    table.n_entries = n_entries;
    table.entry_rows = table.style.v_padding + 1 + table.style.v_padding;
    table.slate_rows = table.n_entries * table.entry_rows + 1;
    table.n_rows = table.n_slates * table.slate_rows + table.n_slates + 1;
    memset(table.slates,  0, sizeof(table.slates));

    if (table.n_rows > MAX_TABLE_ROWS)
    {
        fprintf(stderr, "number of table rows greater than supported. terminating");
        return;
    }

    for (int i = 0; i < n_slates; i++)
    {
        memset(table.rows[i],  '\0', sizeof(table.rows[i]));
    }
    for (int i = 0; i < n_slates; i++)
    {
        for (int j = 0; j < n_entries; j++)
        {
            table.slates[i].visible_capacity[j]   = style.width - style.h_padding*2 - 2;
            table.slates[i].invisible_capacity[j] = MAX_TABLE_ROWS - table.slates[i].visible_capacity[j];
        }
    }

    for (int i = 0; i < n_slates; i++)
    {
        for (int j = 0; j < n_entries; j++)
        {
            table.slates[i].cursor_save_point[j] = style.h_padding + 1;
        }
    }

    fill_table(' ');

    //horizontal seps
    for (int i = 0; i < table.n_rows; i += table.slate_rows + 1)
    {
        for (int j = 0; j < table.style.width; j++)
        {
            table.rows[i][j] = table.style.h_sep;
        }
    }

    //heading seps
    for (int i = 2 + table.style.v_padding * 2; i < table.n_rows; i += table.slate_rows + 1)
    {
        for (int j = 0; j < table.style.width; j++)
        {
            table.rows[i][j] = table.style.heading_sep;
        }
    }

    for (int i = 0; i < table.n_rows; i ++)
    {
        table.rows[i][0] = table.style.v_sep;
        table.rows[i][table.style.width - 1] = table.style.v_sep;
    }
}

typedef struct{
    int visible_len;
    int invisible_len;
} len_pair;

#define ALPH_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
static len_pair ansi_skip(const char *string)
{
    len_pair offsets = {0};
    for (const char *ptr = string; *ptr != '\0'; ptr++)
    {
        if (*ptr == '\033')
        {
            offsets.invisible_len++;
            while(!strchr(ALPH_CHARS, *ptr))
            {
                offsets.invisible_len++;
                ptr++;
            }
            return offsets;
        }
        offsets.visible_len++;
    }
    return offsets;
}


static inline int slate_get_row(int slate_index, int entry_index)
{
    return 1 + table.style.v_padding + slate_index * (table.slate_rows + 1) + (entry_index > 0 ? 1 : 0) + entry_index * table.entry_rows;
}

void table_slate_clear(int slate_index, int entry_index)
{
    int row = slate_get_row(slate_index, entry_index);
    for (int i = 1 + table.style.h_padding; i < MAX_ROW_LEN; i++)
    {
        table.rows[row][i] = '\0';
    }
    for (int i = 1 + table.style.h_padding; i < table.style.width; i++)
    {
        table.rows[row][i] = ' ';
    }
    table.rows[row][table.style.width-1] = table.style.v_sep;

    table.slates[slate_index].cursor_save_point[entry_index] = table.style.h_padding + 1;
    table.slates[slate_index].visible_capacity[entry_index]  = table.style.width - table.style.h_padding*2 - 2;
    table.slates[slate_index].invisible_capacity[entry_index] = MAX_TABLE_ROWS - table.slates[slate_index].visible_capacity[entry_index];
}

void table_slate_printf(int slate_index, int entry_index, const char *fmt, ...)
{
    assert (entry_index < table.n_entries && "tried to access out of bounds entry");
    assert (slate_index < table.n_slates && "tried to access out of bounds slate");

    char buffer[MAX_ROW_LEN];

    va_list args;
    va_start (args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args); 
    va_end(args);

    int *visible_capacity   = &table.slates[slate_index].visible_capacity[entry_index];
    int *invisible_capacity = &table.slates[slate_index].invisible_capacity[entry_index];
    const int row = 1 + table.style.v_padding + slate_index * (table.slate_rows + 1) + (entry_index > 0 ? 1 : 0) + entry_index * table.entry_rows;

    int str_pos       = 0;
    int cursor        = table.slates[slate_index].cursor_save_point[entry_index];
    int visible_len   = 0;
    int invisible_len = 0;
    int invisible_prints = 0;

    do {
        len_pair offsets = ansi_skip(&buffer[str_pos]);
        visible_len = offsets.visible_len;
        invisible_len = offsets.invisible_len;
        invisible_prints += invisible_len;
        int processed_len = 0;

        for (int i = 0; i < visible_len && *visible_capacity > 0; i++, (*visible_capacity)--, cursor++, str_pos++, processed_len++)
        {
            table.rows[row][cursor] = buffer[str_pos];
            if (*visible_capacity <= 3)
                table.rows[row][cursor] = '.';
        }

        if (invisible_len == 0) continue;

        if (invisible_len + 1 > (*invisible_capacity)) 
            fprintf(stderr, "ansi character capacity not enough to print ansi characters, skipping");

        for (int i = 0; i < invisible_len; i++, (*invisible_capacity)--, cursor++, str_pos++) 
        {
            table.rows[row][cursor] = buffer[str_pos + visible_len - processed_len];
        }
    }
    while ((visible_len > 0 && *visible_capacity > 0) || (invisible_len > 0 && (*invisible_capacity) > 0));
    table.slates[slate_index].cursor_save_point[entry_index] = cursor;

    for (int i = 0; i < *visible_capacity + table.style.h_padding; i++, cursor++)
    {
        table.rows[row][cursor] = ' ';
    }
    table.rows[row][cursor] = '|';
}

void table_flush()
{
    for (int i = 0; i < table.n_rows; i++)
    {
        printf("%s\n", table.rows[i]);
    }
}
