# Makefile for Session CLI

FPC = fpc
SRC_DIR = src
TEST_DIR = tests
DATA_DIR = data
BIN_DIR = bin

# Paths for libraries (adjust if needed)
LIB_PATHS = -Fl/usr/local/lib -Fl/usr/lib/x86_64-linux-gnu

# Compilation flags
FPC_FLAGS = -Fu$(SRC_DIR) -Fu$(TEST_DIR) -FE$(BIN_DIR) $(LIB_PATHS) -O2
FPC_TEST_FLAGS = $(FPC_FLAGS) -gh  # Enable heaptrc for tests

# Targets
all: build tests

build:
	mkdir -p $(BIN_DIR)
	$(FPC) $(FPC_FLAGS) $(SRC_DIR)/session-cli.lpr -osession-cli

tests:
	mkdir -p $(BIN_DIR)
	$(FPC) $(FPC_TEST_FLAGS) $(TEST_DIR)/test_all.lpr -otest_all

clean:
	rm -rf $(BIN_DIR)
	rm -f $(SRC_DIR)/*.o $(SRC_DIR)/*.ppu
	rm -f $(TEST_DIR)/*.o $(TEST_DIR)/*.ppu

.PHONY: all build tests clean
