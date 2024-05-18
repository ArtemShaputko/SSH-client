TARGET = sc

OBJDIR = obj
SRCDIR = src

CC = gcc

CFLAGS = -Wall -Wextra -g -lpam -W -Wall -std=c11 -pedantic -I/usr/include/libssh
LIBSSH = -L/usr/lib -lssh

SOURCES = $(shell find $(SRCDIR) -name '*.c')
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBSSH)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJDIR) $(TARGET)

.PHONY: all clean