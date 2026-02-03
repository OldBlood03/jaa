#ifndef TABLE
#define TABLE

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
void table_slate_clear(int slate_index, int entry_index);
void table_flush();

#endif//TABLE
