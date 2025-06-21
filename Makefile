CC=gcc

SRC_DIR=./src
BIN_DIR=./bin
OBJ_DIR=./obj
INCLUDE_DIRS=-I$(SRC_DIR)

SRV_BIN=$(BIN_DIR)/server
CLI_BIN=$(BIN_DIR)/client

SRCS=$(wildcard $(SRC_DIR)/*.c)
SRV_SRCS:=$(filter-out $(SRC_DIR)/client.c,$(SRCS))
CLI_SRCS:=$(filter-out $(SRC_DIR)/server.c,$(SRCS))

SRV_OBJS=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRV_SRCS))
CLI_OBJS=$(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(CLI_SRCS))

LIBS=

.PHONY: mkdir all

all: server client

server: mkdir $(SRV_OBJS)
	$(CC) $(INCLUDE_DIRS) $(SRV_OBJS) -o $(SRV_BIN) $(LIBS)

client: mkdir $(CLI_OBJS)
	$(CC) $(INCLUDE_DIRS) $(CLI_OBJS) -o $(CLI_BIN) $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(INCLUDE_DIRS) -c $^ -o $@ $(LIBS)

mkdir:
	@if [ ! -d bin ]; then mkdir bin; fi
	@if [ ! -d obj ]; then mkdir obj; fi

clean:
	@rm bin -r
	@rm obj -r
