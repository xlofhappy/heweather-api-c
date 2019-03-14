CC = gcc
CFLAGS = -g -Wall
INCLUDES = -I./include
LDFLAGS = -L./lib
LIBS = -lm -lssl -lcrypto
TARGET = ssl_client
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

.PHONY: depend clean

all: $(TARGET)
	@echo  Simple compiler named mycc has been compiled

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(OBJS) $(LDFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	$(RM) *.o *~ $(TARGET)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

# DO NOT DELETE THIS LINE -- make depend needs it
