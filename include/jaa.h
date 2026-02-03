#ifndef JAA
#define JAA
#include "defs.h"

int  find_config_file(char *filename_out, size_t capacity);
int  init_config_from_file(const char *filename);
void distribute();
#endif//JAA
