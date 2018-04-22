CFLAGS =     -ggdb -std=c99 -Wall -Wextra -pedantic -O2 -pthread
LOCAL_LIBS = pktUtility.o
CLIBFLAGS = $(LOCAL_LIBS) -lm -lpthread 

.PRECIOUS: $(LOCAL_LIBS)

.phony: fifos

# make the named pipes
fifos: all
	@if [ ! -p ToFirewall ]; then mkfifo ToFirewall; fi
	@if [ ! -p FromFirewall ]; then mkfifo FromFirewall; fi

