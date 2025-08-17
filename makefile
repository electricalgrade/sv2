#- -------- Config --------
CC      ?= gcc
CSTD    ?= c11
CFLAGS  ?= -O2 -g -std=$(CSTD) -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align -Wstrict-prototypes -pedantic -MMD -MP
LDFLAGS ?=
LDLIBS  ?= -pthread

# Include paths
INCLUDES := -Isrc/sv2

# Output dirs
BUILD_DIR := build
OBJ_DIR   := $(BUILD_DIR)/obj
BIN_DIR   := $(BUILD_DIR)/bin

# Source layout
SV2_SRC := \
  src/sv2/sv2_wire.c \
  src/sv2/sv2_common.c \
  src/sv2/sv2_mining.c \
  src/sv2/sv2_adapter.c

SV2_HDR := \
  src/sv2/sv2_wire.h \
  src/sv2/sv2_common.h \
  src/sv2/sv2_mining.h \
  src/sv2/sv2_adapter.h

DEMO_SRC := \
  src/sv2_server.c \
  src/sv2_client.c

TESTS_SRC := \
  tests/test_sv2_adapter.c

# Objects
SV2_OBJ    := $(SV2_SRC:%.c=$(OBJ_DIR)/%.o)
DEMO_OBJ   := $(DEMO_SRC:%.c=$(OBJ_DIR)/%.o)
TESTS_OBJ  := $(TESTS_SRC:%.c=$(OBJ_DIR)/%.o)

# Binaries
SV2_SERVER := $(BIN_DIR)/sv2_server
SV2_CLIENT := $(BIN_DIR)/sv2_client
TEST_ADAPT := $(BIN_DIR)/test_sv2_adapter

# Default target
.PHONY: all
all: $(SV2_SERVER) $(SV2_CLIENT) $(TEST_ADAPT)

# -------- Build rules --------

# Create needed directories
$(BIN_DIR) \
$(OBJ_DIR) \
$(OBJ_DIR)/src \
$(OBJ_DIR)/src/sv2 \
$(OBJ_DIR)/tests:
	@mkdir -p $@

# Pattern rule for objects (keeps source subpaths under build/obj/)
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR) $(OBJ_DIR)/src $(OBJ_DIR)/src/sv2 $(OBJ_DIR)/tests
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link demo binaries (use the exact object paths in DEMO_OBJ)
$(SV2_SERVER): $(OBJ_DIR)/src/sv2_server.o $(SV2_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(SV2_CLIENT): $(OBJ_DIR)/src/sv2_client.o $(SV2_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

# Link test binary (optional)
$(TEST_ADAPT): $(OBJ_DIR)/tests/test_sv2_adapter.o $(SV2_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

# -------- Convenience targets --------

.PHONY: run-server run-client run-test
run-server: $(SV2_SERVER)
	$(SV2_SERVER) 3333

run-client: $(SV2_CLIENT)
	$(SV2_CLIENT) 127.0.0.1 3333

run-test: $(TEST_ADAPT)
	$(TEST_ADAPT) 3333

# -------- Cleaning --------

.PHONY: clean distclean
clean:
	$(RM) -r $(BUILD_DIR)

distclean: clean

# -------- Dependencies --------
-include $(SV2_OBJ:.o=.d)
-include $(DEMO_OBJ:.o=.d)
-include $(TESTS_OBJ:.o=.d)
