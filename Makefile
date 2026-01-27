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
client: all
	LSAN_OPTIONS=suppressions=asan.supp ./app -c
host:
	LSAN_OPTIONS=suppressions=asan.supp ./app -h
debug: all
	gdb ./app
clean:
	rm app
