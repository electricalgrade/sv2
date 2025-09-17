# -------- Config --------
CC      = gcc
CSTD    = c11
CFLAGS  =  -O2 -g -std=$(CSTD) -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align -Wstrict-prototypes -pedantic
LDFLAGS =  -L/usr/local/lib
LDLIBS  = -lnoiseprotocol -lnoisekeys -lnoiseprotobufs 
# Include paths
INCLUDES := -Isrc -Isv2_src/sv2 -I/usr/local/include

# Output dirs
BUILD_DIR := build
OBJ_DIR   := $(BUILD_DIR)/obj
BIN_DIR   := $(BUILD_DIR)/bin

# SV2 wire/common (use your existing sources here)
SV2_SRC := \
  sv2_src/sv2/sv2_wire.c \
  sv2_src/sv2/sv2_common.c \
  sv2_src/sv2/sv2_mining.c

SV2_HDR := \
  sv2_src/sv2/sv2_wire.h \
  sv2_src/sv2/sv2_common.h \
  sv2_src/sv2/sv2_mining.h

# Noise wrapper
NOISE_SRC := \
  src/sv2_noise.c 
NOISE_HDR := \
  src/sv2_noise.h 


# Mining dispatcher (server-side loop after SetupConnection)
MINING_SRC := src/mining_dispatch.c
MINING_HDR := src/mining_dispatch.h
MINING_OBJ := $(MINING_SRC:%.c=$(OBJ_DIR)/%.o)

# Apps
APP_SERVER := src/sv2_pool_server.c
APP_CLIENT := src/noise_client.c

# Objects
SV2_OBJ     := $(SV2_SRC:%.c=$(OBJ_DIR)/%.o)
NOISE_OBJ   := $(NOISE_SRC:%.c=$(OBJ_DIR)/%.o)
SERVER_OBJ  := $(APP_SERVER:%.c=$(OBJ_DIR)/%.o)
CLIENT_OBJ  := $(APP_CLIENT:%.c=$(OBJ_DIR)/%.o)

# Binaries
POOL_SERVER := $(BIN_DIR)/sv2_pool_server
NOISE_CLIENT:= $(BIN_DIR)/noise_client

# Default target
.PHONY: all
all: $(POOL_SERVER) $(NOISE_CLIENT)

# Create needed directories
$(BIN_DIR) \
$(OBJ_DIR) \
$(OBJ_DIR)/src \
$(OBJ_DIR)/sv2_src \
$(OBJ_DIR)/sv2_src/sv2:
	@mkdir -p $@

# Compile rules
$(OBJ_DIR)/%.o: %.c $(SV2_HDR) $(NOISE_HDR) $(MINING_HDR) |  $(OBJ_DIR) $(OBJ_DIR)/src $(OBJ_DIR)/sv2_src $(OBJ_DIR)/sv2_src/sv2
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link apps
$(POOL_SERVER): $(SERVER_OBJ) $(NOISE_OBJ) $(SV2_OBJ) $(MINING_OBJ) | $(BIN_DIR) 
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(NOISE_CLIENT): $(CLIENT_OBJ) $(SV2_OBJ) $(NOISE_OBJ)| $(BIN_DIR) 
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

# Convenience
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: run-server
run-server: $(POOL_SERVER)
	$(POOL_SERVER) -l 0.0.0.0:3334 --prologue STRATUM/2

.PHONY: run-server-ik
run-server-ik: $(POOL_SERVER)
	$(POOL_SERVER) -l 0.0.0.0:3334 --ik --prologue STRATUM/2

.PHONY: run-client
run-client: $(NOISE_CLIENT)
	$(NOISE_CLIENT) -l 127.0.0.1:3334 --prologue STRATUM/2
