LIBS   := -lssh

LIBPATHS := dependencies/lib/
INCPATHS := dependencies/include/ include/

LFLAGS := -fsanitize=address,undefined $(addprefix -L, $(LIBPATHS)) $(LIBS) 
CFLAGS := -g -Wextra -Wall -Werror -fsanitize=address,undefined $(addprefix -I, $(INCPATHS)) -fanalyzer 

RELEASE_LFLAGS := $(addprefix -L, $(LIBPATHS)) $(LIBS) 
RELEASE_CFLAGS := $(addprefix -I, $(INCPATHS)) -O3

.PHONY: all run debug

all:
	gcc $(CFLAGS) src/main.c src/table.c src/jaa.c -o jaa $(LFLAGS)

release:
	gcc $(RELEASE_CFLAGS) src/main.c src/table.c src/jaa.c -o jaa $(RELEASE_LFLAGS)

run:
	LSAN_OPTIONS=suppressions=asan.supp ./jaa 
debug: all
	LSAN_OPTIONS=verbosity=1:log_threads=1 gdb ./jaa
clean:
	rm jaa
