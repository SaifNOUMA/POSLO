.PHONY: clean all 

CC=g++
CC_FLAGS=-O3 -fopenmp
CC_LIBS=-lssl -lcrypto
INC_DIR=-I./misc -I./fourq -I./oslo
OBJ_DIR = bin

SRC_FILES=fourq/fp.c oslo/util.cpp oslo/oslo_smf.cpp oslo/oslo_sgn.cpp oslo/oslo_test.cpp main.cpp

# Output binaries
BIN_AES128_SHA256=$(OBJ_DIR)/oslo_aes128_sha256
BIN_AES128_ARITHM=$(OBJ_DIR)/oslo_aes128_arithm
BIN_AES128_AES128=$(OBJ_DIR)/oslo_aes128_aes128
BIN_SHA256_SHA256=$(OBJ_DIR)/oslo_sha256_sha256
BIN_SHA256_ARITHM=$(OBJ_DIR)/oslo_sha256_arithm

all: $(BIN_AES128_SHA256) $(BIN_AES128_ARITHM) $(BIN_SHA256_SHA256) $(BIN_SHA256_ARITHM) $(BIN_AES128_AES128)
# all: $(BIN_AES128_AES128) 

$(BIN_AES128_SHA256):
	$(CC) $(CC_FLAGS) -D SeedMethod_AES128 -D HashMethod_SHA256 $(SRC_FILES) -o $@ $(INC_DIR) $(CC_LIBS)

$(BIN_AES128_ARITHM):
	$(CC) $(CC_FLAGS) -D SeedMethod_AES128 -D HashMethod_ARITHM $(SRC_FILES) -o $@ $(INC_DIR) $(CC_LIBS)

$(BIN_AES128_AES128):
	$(CC) $(CC_FLAGS) -D SeedMethod_AES128 -D HashMethod_AES128 $(SRC_FILES) -o $@ $(INC_DIR) $(CC_LIBS)

$(BIN_SHA256_SHA256):
	$(CC) $(CC_FLAGS) -D SeedMethod_SHA256 -D HashMethod_SHA256 $(SRC_FILES) -o $@ $(INC_DIR) $(CC_LIBS)

$(BIN_SHA256_ARITHM):
	$(CC) $(CC_FLAGS) -D SeedMethod_SHA256 -D HashMethod_ARITHM $(SRC_FILES) -o $@ $(INC_DIR) $(CC_LIBS)

clean:
	$(RM) $(BIN_AES128_SHA256) $(BIN_AES128_ARITHM) $(BIN_AES128_AES128) $(BIN_SHA256_SHA256) $(BIN_SHA256_ARITHM)
