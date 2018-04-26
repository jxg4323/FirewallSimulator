#
# Created by gmakemake (Ubuntu Jul 25 2014) on Thu Apr 26 12:59:18 2018
#

#
# Definitions
#

.SUFFIXES:
.SUFFIXES:	.a .o .c .C .cpp .s .S
.c.o:
		$(COMPILE.c) $<
.C.o:
		$(COMPILE.cc) $<
.cpp.o:
		$(COMPILE.cc) $<
.S.s:
		$(CPP) -o $*.s $<
.s.o:
		$(COMPILE.cc) $<
.c.a:
		$(COMPILE.c) -o $% $<
		$(AR) $(ARFLAGS) $@ $%
		$(RM) $%
.C.a:
		$(COMPILE.cc) -o $% $<
		$(AR) $(ARFLAGS) $@ $%
		$(RM) $%
.cpp.a:
		$(COMPILE.cc) -o $% $<
		$(AR) $(ARFLAGS) $@ $%
		$(RM) $%

CC =		gcc
CXX =		g++

RM = rm -f
AR = ar
LINK.c = $(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS)
LINK.cc = $(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS)
COMPILE.c = $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE.cc = $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c
CPP = $(CPP) $(CPPFLAGS)
########## Flags from header.mak

CFLAGS =     -ggdb -std=c99 -Wall -Wextra -pedantic -O2 -pthread
LOCAL_LIBS = pktUtility.o
CLIBFLAGS = $(LOCAL_LIBS) -lm -lpthread 

.PRECIOUS: $(LOCAL_LIBS)

.phony: fifos

# make the named pipes
fifos: all
	@if [ ! -p ToFirewall ]; then mkfifo ToFirewall; fi
	@if [ ! -p FromFirewall ]; then mkfifo FromFirewall; fi


########## End of flags from header.mak


CPP_FILES =	
C_FILES =	filter.c firewall.c
PS_FILES =	
S_FILES =	
H_FILES =	filter.h pktUtility.h
SOURCEFILES =	$(H_FILES) $(CPP_FILES) $(C_FILES) $(S_FILES)
.PRECIOUS:	$(SOURCEFILES)
OBJFILES =	filter.o 

#
# Main targets
#

all:	firewall 

firewall:	firewall.o $(OBJFILES)
	$(CC) $(CFLAGS) -o firewall firewall.o $(OBJFILES) $(CLIBFLAGS) 

#
# Dependencies
#

filter.o:	filter.h pktUtility.h
firewall.o:	filter.h

#
# Housekeeping
#

Archive:	archive.tgz

archive.tgz:	$(SOURCEFILES) Makefile
	tar cf - $(SOURCEFILES) Makefile | gzip > archive.tgz

clean:
	-/bin/rm -f $(OBJFILES) firewall.o core

realclean:        clean
	-/bin/rm -f firewall 
