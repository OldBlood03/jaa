#include "ui.h"
#include "termbox2/termbox2.h"
#include "darray.h"
#include <stdbool.h>
#include "jaa.h"

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
        case TB_ERR_NO_EVENT:\
            assert(0 && "an TB_ERR_NO_EVENT error occurred when calling function " #retval);\
        case TB_ERR_NO_TERM:\
            assert(0 && "an TB_ERR_NO_TERM error occurred when calling function " #retval);\
        case TB_ERR_NOT_INIT:\
            assert(0 && "an TB_ERR_NOT_INIT error occurred when calling function " #retval);\
        case TB_ERR_OUT_OF_BOUNDS:\
            assert(0 && "an TB_ERR_OUT_OF_BOUNDS error occurred when calling function " #retval);\
        case TB_ERR_READ:\
            assert(0 && "an TB_ERR_READ error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_IOCTL:\
            assert(0 && "an TB_ERR_RESIZE_IOCTL error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_PIPE:\
            assert(0 && "an TB_ERR_RESIZE_PIPE error occurred when calling function " #retval);\
        case TB_ERR_RESIZE_SIGACTION:\
            assert(0 && "an TB_ERR_RESIZE_SIGACTION error occurred when calling function " #retval);\
        case TB_ERR_POLL:\
            assert(0 && "an TB_ERR_POLL error occurred when calling function " #retval);\
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

#define LEFT_MARGIN 3

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

void jaa_ui_create()
{
    tb_check(tb_init());
    tb_check(tb_hide_cursor());
}

static void draw_cmds(darray(char *) cmds)
{
    int retval = tb_width();
    tb_check(retval);
    int halfway = retval / 2;
    tb_check(tb_printf(halfway, 0, TB_WHITE, TB_DEFAULT, "QUEUE:"));
    for (int i = 0; i < darray_size(cmds); i++)
    {
        const char *cmd = cmds[i];
        tb_check(tb_printf(halfway, i + 1, TB_WHITE, TB_DEFAULT, "%s", cmd));
    }
}

static void draw_pool(darray(host) pool)
{
    for (int i = 0; i < darray_size(pool); i++)
    {
        host h = pool[i];

        sanitize_string(h.stdout_buffer);
        sanitize_string(h.stderr_buffer);
        sanitize_string(h.status_buffer);

        tb_check(tb_printf(LEFT_MARGIN,6*i, TB_WHITE, TB_DEFAULT, "address: %s", h.addr));
        tb_check(tb_printf(LEFT_MARGIN,6*i + 1, TB_WHITE, TB_DEFAULT, "status: %s", h.status_buffer));
        tb_check(tb_printf(LEFT_MARGIN,6*i + 2, TB_WHITE, TB_DEFAULT, "stdout: %s", h.stdout_buffer));
        tb_check(tb_printf(LEFT_MARGIN,6*i + 3, TB_WHITE, TB_DEFAULT, "stderr: %s", h.stderr_buffer));
        tb_check(tb_printf(LEFT_MARGIN,6*i + 4, TB_WHITE, TB_DEFAULT, "%s", h.is_busy ? "busy" : "idle"));
    }
}

void jaa_ui_update(job j)
{
    tb_check(tb_clear());
    draw_pool(j.pool);
    draw_cmds(j.cmds);
    tb_check(tb_present());
}

bool jaa_ui_should_shutdown()
{
    struct tb_event ev;
    int res = tb_peek_event(&ev, 10); 
    
    if (res == TB_OK) {
        return ev.type == TB_EVENT_KEY && ev.key == TB_KEY_CTRL_C;
    }
    
    return false;
}

void jaa_ui_destroy()
{
    tb_check(tb_shutdown());
}
