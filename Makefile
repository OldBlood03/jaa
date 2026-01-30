LIBS   := -lssh

LIBPATHS := dependencies/lib/
INCPATHS := dependencies/include/

LFLAGS := -fsanitize=address,undefined $(addprefix -L, $(LIBPATHS)) $(LIBS) 
CFLAGS := -g -Wextra -Wall -Werror -fsanitize=address,undefined $(addprefix -I, $(INCPATHS)) -fanalyzer 

.PHONY: all run debug

all:
	gcc $(CFLAGS) src/main.c -o app $(LFLAGS)
run: all
	LSAN_OPTIONS=suppressions=asan.supp ./app 
debug: all
	LSAN_OPTIONS=verbosity=1:log_threads=1 gdb ./app
clean:
	rm app
