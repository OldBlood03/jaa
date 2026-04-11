CC := gcc
LIBS := -lssh -ltermbox2 -lpthread

LIBPATHS := dependencies/lib/
INCPATHS := dependencies/include/ include/

LFLAGS := -fsanitize=address,undefined $(addprefix -L, $(LIBPATHS)) $(foreach dir, $(LIBPATHS), -Wl,-rpath=$(dir)) $(LIBS)
CFLAGS := -g -Wextra -Wall -Werror -fsanitize=address,undefined $(addprefix -I, $(INCPATHS)) -fanalyzer -fopenmp

RELEASE_LFLAGS := $(addprefix -L, $(LIBPATHS)) $(LIBS) 
RELEASE_CFLAGS := $(addprefix -I, $(INCPATHS)) -O3

.PHONY: all run debug test

all:
	$(CC) $(CFLAGS) src/main.c src/ui.c src/jaa.c -o jaa $(LFLAGS)

release:
	$(CC) $(RELEASE_CFLAGS) src/main.c src/jaa.c -o jaa $(RELEASE_LFLAGS)

run: all
	LSAN_OPTIONS=suppressions=asan.supp ./jaa 
debug: all
	LSAN_OPTIONS=verbosity=1:log_threads=1 gdb ./jaa
clean:
	rm jaa
