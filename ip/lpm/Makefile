srcdir          = ./
VPATH           = ./

CC = gcc

LIBSTATIC = lpm.a
SHARED = lpm.so

OBJS = lpm.o 

all: lpm.so

%.o: %.c
	$(CC) -c -fPIC $<

static: $(LIBSTATIC)
shared: $(SHARED)

$(LIBSTATIC): $(OBJS)
	ar -cr $@ $(OBJS)

lpm.o:
	gcc -c -fPIC lpm.c

$(SHARED): lpm.o
	gcc -shared lpm.o -o lpm.so
clean:
	rm -f *.o *.a *.so
