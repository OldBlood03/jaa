#include "ui.h"
#include "termbox2/termbox2.h"
#include "darray.h"
#include <stdbool.h>
#include "jaa.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <signal.h>

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

#define tb_check(retval) \
    switch(retval)\
    {\
        case TB_ERR:\
            assert(0 && "an TB_ERR error occurred when calling function " #retval);\
        case TB_ERR_NEED_MORE:\
            assert(0 && "an TB_ERR_NEED_MORE error occurred when calling function " #retval);\
        case TB_ERR_INIT_ALREADY:\
            assert(0 && "an TB_ERR_INIT_ALREADY error occurred when calling function " #retval);\
        case TB_ERR_INIT_OPEN:\
            assert(0 && "an TB_ERR_INIT_OPEN error occurred when calling function " #retval);\
        case TB_ERR_MEM:\
            assert(0 && "an TB_ERR_MEM error occurred when calling function " #retval);\
        case TB_ERR_NO_TERM:\
            assert(0 && "an TB_ERR_NO_TERM error occurred when calling function " #retval);\
        case TB_ERR_NOT_INIT:\
            assert(0 && "an TB_ERR_NOT_INIT error occurred when calling function " #retval);\
        case TB_ERR_OUT_OF_BOUNDS:\
            assert(0 && "an TB_ERR_OUT_OF_BOUNDS error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_IOCTL:\
            assert(0 && "an TB_ERR_RESIZE_IOCTL error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_PIPE:\
            assert(0 && "an TB_ERR_RESIZE_PIPE error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_SIGACTION:\
            assert(0 && "an TB_ERR_RESIZE_SIGACTION error occurred when calling function " #retval);\
        case TB_ERR_POLL:\
            assert(0 && "an TB_ERR_POLL error occurred when calling function " #retval);\
        case TB_ERR_READ:\
            assert(0 && "an TB_ERR_NO_EVENT error occurred when calling function " #retval);\
        case TB_ERR_TCGETATTR:\
            assert(0 && "an TB_ERR_TCGETATTR error occurred when calling function " #retval);\
        case TB_ERR_TCSETATTR:\
            assert(0 && "an TB_ERR_TCSETATTR error occurred when calling function " #retval);\
        case TB_ERR_UNSUPPORTED_TERM:\
            assert(0 && "an TB_ERR_UNSUPPORTED_TERM error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_WRITE:\
            assert(0 && "an TB_ERR_RESIZE_WRITE error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_POLL:\
            assert(0 && "an TB_ERR_RESIZE_POLL error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_READ:\
            assert(0 && "an TB_ERR_RESIZE_READ error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_SSCANF:\
            assert(0 && "an TB_ERR_RESIZE_SSCANF error occurred when calling function " #retval);\
        case TB_ERR_CAP_COLLISION:\
            assert(0 && "an TB_ERR_CAP_COLLISION error occurred when calling function " #retval);\
        default:\
            break;\
    }

#define NULL_TERMINATOR 1
#define LEFT_MARGIN 3

static struct {
    darray(char *) rows;
    int y;
    int width;
    int height;
} window;

static void sanitize_string(char *str)
{
    if (!str) return;
    for (int i = 0; str[i] != '\0'; i++)
    {
        if (str[i] == '\n' || str[i] == '\r' || str[i] == '\t')
        {
            str[i] = ' ';
        }
    }
}

static void add_rows (int n)
{
    for (int i = 0; i < n; i++)
    {
        char *row = malloc(window.width + NULL_TERMINATOR);
        memset(row, ' ', window.width);
        row[window.width] = '\0';
        darray_push_back(window.rows, row);
    }
}

void jaa_ui_create()
{
    tb_check(tb_init());
    tb_check(tb_hide_cursor());
    tb_set_input_mode(TB_INPUT_ESC | TB_INPUT_MOUSE);
    int width = tb_width();
    int height = tb_height();
    tb_check(width);
    tb_check(height);

    window.rows = NULL;
    window.y = 0;
    window.width = width;
    window.height = height;

    add_rows(height);
}

static void window_printf (int x, int y, const char *fmt, ...)
{
    add_rows(y - darray_size(window.rows) + 1);
    va_list args;
    va_start(args, fmt);
    if ((window.width - 1) > x)
    {
        int bytes = vsnprintf(window.rows[y] + x, (window.width - 1) - x, fmt, args);
        int end = MIN(x + bytes, window.width);
        window.rows[y][end] = ' ';
    }
    sanitize_string(window.rows[y]);
    va_end(args);
}

static void window_clear()
{
    for (int i = 0; i < darray_size(window.rows); i++)
        memset(window.rows[i], ' ', window.width);
    tb_check(tb_clear());
}

static void draw_cmds(darray(char *) cmds)
{
    int halfway = window.width / 2;
    window_printf(halfway, 0, "QUEUE:");
    for (int i = 0; i < darray_size(cmds); i++)
    {
        const char *cmd = cmds[i];
        window_printf(halfway, i + 1, "%s", cmd);
    }
}

static void draw_pool(darray(host) pool)
{
    for (int i = 0; i < darray_size(pool); i++)
    {
        host h = pool[i];
        window_printf(LEFT_MARGIN,6*i, "address: %s", h.addr);
        window_printf(LEFT_MARGIN,6*i + 1, "status: %s", h.status_buffer);
        window_printf(LEFT_MARGIN,6*i + 2, "stdout: %s", h.stdout_buffer);
        window_printf(LEFT_MARGIN,6*i + 3, "stderr: %s", h.stderr_buffer);
        window_printf(LEFT_MARGIN,6*i + 4, "%s", h.is_busy ? "busy" : "idle");
    }
}

static bool should_shutdown = false;
void check_events()
{
    struct tb_event ev;
    int res = tb_peek_event(&ev, 10); 
    tb_check(res);
    
    switch (ev.type)
    {
        case TB_EVENT_MOUSE:
            if (ev.key == TB_KEY_MOUSE_WHEEL_UP)
                window.y = MAX(window.y - 1, 0);
            if (ev.key == TB_KEY_MOUSE_WHEEL_DOWN)
                window.y = MIN(window.y + 1, darray_size(window.rows) - window.height);
            break;
        case TB_EVENT_RESIZE:
            int width = tb_width();
            int height = tb_height();
            tb_check(width);
            tb_check(height);

            if (width > window.width)
            {
                int nrows = darray_size(window.rows);
                for (int i = 0; i < nrows; i++)
                {
                    free(darray_pop(window.rows));

                }
                window.width  = width;
                window.height = height;
                add_rows(nrows);
            }else {
                window.width  = width;
                window.height = height;
            }

            break;
        case TB_EVENT_KEY:
            if (ev.key == TB_KEY_CTRL_C)
                should_shutdown = true;
    }
}

void jaa_ui_update(job *j)
{
    window_clear();
    check_events();
    draw_pool(j->pool);
    draw_cmds(j->cmds);
    for (int i = 0; i < window.height; i++)
    {
        tb_check(tb_print(0, i, TB_WHITE, TB_DEFAULT, window.rows[window.y + i]));
    }
    tb_check(tb_present());
}

bool jaa_ui_should_shutdown()
{
    return should_shutdown;
}

void jaa_ui_destroy()
{
    for (int i = 0; i < darray_size(window.rows); i++)
        free(window.rows[i]);
    darray_free(window.rows);
    tb_check(tb_shutdown());
}
