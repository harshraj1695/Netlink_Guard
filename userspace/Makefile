CC := gcc
CFLAGS := -Wall -Wextra -O2
BIN_DIR := bin

all: $(BIN_DIR)/kgctl

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/kgctl: cli/kgctl.c common/protocol.h | $(BIN_DIR)
	$(CC) $(CFLAGS) cli/kgctl.c -o $(BIN_DIR)/kgctl

clean:
	rm -rf $(BIN_DIR)
