CC = gcc
CFLAGS = -Wall -Wextra -O2

# Source codes (all .c files in the directory)
SRC = $(wildcard *.c)

# Objects in the build/ directory
OBJDIR = build
OBJ = $(patsubst %.c,$(OBJDIR)/%.o,$(SRC))

TARGET = attack

all: $(OBJDIR) $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)

.PHONY: all clean

