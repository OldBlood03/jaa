CC := gcc
LIBS := -lssh -lpthread

LIBPATHS := dependencies/lib/
INCPATHS := dependencies/include/ include/

LFLAGS := $(addprefix -L, $(LIBPATHS)) $(foreach dir, $(LIBPATHS), -Wl,-rpath=$(abspath $(dir))) $(LIBS) -fsanitize=address,undefined 
CFLAGS := -fopenmp $(addprefix -I, $(INCPATHS)) -g -Wextra -Wall -Werror -fanalyzer -fsanitize=address,undefined -DTB_IMPL

RELEASE_LFLAGS := $(addprefix -L, $(LIBPATHS)) $(LIBS) 
RELEASE_CFLAGS := -fopenmp $(addprefix -I, $(INCPATHS)) -O3 -DTB_IMPL

.PHONY: all run debug test

all:
	$(CC) $(CFLAGS) src/main.c src/ui.c src/jaa.c -o jaa $(LFLAGS)

release:
	$(CC) $(RELEASE_CFLAGS) src/main.c src/ui.c src/jaa.c -o jaa $(RELEASE_LFLAGS)

run: all
	LSAN_OPTIONS='suppressions=asan.supp' ./jaa 
debug: all
	LSAN_OPTIONS=verbosity=1:log_threads=1 gdb ./jaa
clean:
	rm jaa
