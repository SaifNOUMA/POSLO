# Paths and Directories
CUDA_ROOT_DIR=/usr/local/cuda-11.8
SRC_DIR = ..
OBJ_DIR = bin

# Compiler and Linker Configurations
CC=g++
CC_FLAGS=-O3
CC_LIBS=
NVCC=$(CUDA_ROOT_DIR)/bin/nvcc
CUDA_LIB_DIR= -L$(CUDA_ROOT_DIR)/lib64
CUDA_INC_DIR= -I$(CUDA_ROOT_DIR)/include
CUDA_LINK_LIBS= -lm -lssl -lcrypto

# Compiler Flags
NVCC_FLAGS = -std=c++17 -use_fast_math -dlto -dc -rdc=true -O3 -arch=sm_80 -lnvToolsExt
#  --ptxas-options=-v 

# all: oslo_sha256_sha256
# all: oslo_aes128_aes128
# all: oslo_aes128_sha256 oslo_aes128_aes128 oslo_aes128_arithm oslo_sha256_sha256 oslo_sha256_arithm
all:  oslo_aes128_aes128 oslo_aes128_arithm oslo_sha256_sha256 
# all: oslo_aes128_arithm

oslo_aes128_sha256: NVCC_FLAGS += -D OSLO_AES128_SHA256
oslo_aes128_sha256:
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/fourq/fp.c -o $(OBJ_DIR)/fp.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/util.cu -o $(OBJ_DIR)/util.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/oslo.cu -o $(OBJ_DIR)/oslo.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c main.cu -o $(OBJ_DIR)/main.o
	$(NVCC) -O3 -arch=sm_80 $(CUDA_INC_DIR) $(CUDA_LIB_DIR) $(CUDA_LINK_LIBS) $(OBJ_DIR)/fp.o $(OBJ_DIR)/util.o $(OBJ_DIR)/oslo.o $(OBJ_DIR)/main.o -o $(OBJ_DIR)/$@

oslo_aes128_arithm: NVCC_FLAGS += -D OSLO_AES128_ARITHM
oslo_aes128_arithm:
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/fourq/fp.c -o $(OBJ_DIR)/fp.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/util.cu -o $(OBJ_DIR)/util.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/oslo.cu -o $(OBJ_DIR)/oslo.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c main.cu -o $(OBJ_DIR)/main.o
	$(NVCC) -O3 -arch=sm_80 $(CUDA_INC_DIR) $(CUDA_LIB_DIR) $(CUDA_LINK_LIBS) $(OBJ_DIR)/fp.o $(OBJ_DIR)/util.o $(OBJ_DIR)/oslo.o $(OBJ_DIR)/main.o -o $(OBJ_DIR)/$@

oslo_aes128_aes128: NVCC_FLAGS += -D OSLO_AES128_AES128
oslo_aes128_aes128:
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/fourq/fp.c -o $(OBJ_DIR)/fp.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/util.cu -o $(OBJ_DIR)/util.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/oslo.cu -o $(OBJ_DIR)/oslo.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c main.cu -o $(OBJ_DIR)/main.o
	$(NVCC) -O3 -arch=sm_80 -lnvToolsExt $(CUDA_INC_DIR) $(CUDA_LIB_DIR) $(CUDA_LINK_LIBS) $(OBJ_DIR)/fp.o $(OBJ_DIR)/util.o $(OBJ_DIR)/oslo.o $(OBJ_DIR)/main.o -o $(OBJ_DIR)/$@

oslo_sha256_sha256: NVCC_FLAGS += -D OSLO_SHA256_SHA256
oslo_sha256_sha256:
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/fourq/fp.c -o $(OBJ_DIR)/fp.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/util.cu -o $(OBJ_DIR)/util.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/oslo.cu -o $(OBJ_DIR)/oslo.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c main.cu -o $(OBJ_DIR)/main.o
	$(NVCC) -O3 -arch=sm_80 -maxrregcount=40 -lnvToolsExt $(CUDA_INC_DIR) $(CUDA_LIB_DIR) $(CUDA_LINK_LIBS) $(OBJ_DIR)/fp.o $(OBJ_DIR)/util.o $(OBJ_DIR)/oslo.o $(OBJ_DIR)/main.o -o $(OBJ_DIR)/$@

oslo_sha256_arithm: NVCC_FLAGS += -D OSLO_SHA256_ARITHM
oslo_sha256_arithm:
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/fourq/fp.c -o $(OBJ_DIR)/fp.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/util.cu -o $(OBJ_DIR)/util.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c $(SRC_DIR)/include/oslo.cu -o $(OBJ_DIR)/oslo.o
	$(NVCC) $(NVCC_FLAGS) -I$(SRC_DIR)/ -I$(SRC_DIR)/include -c main.cu -o $(OBJ_DIR)/main.o
	$(NVCC) -O3 -arch=sm_80 $(CUDA_INC_DIR) $(CUDA_LIB_DIR) $(CUDA_LINK_LIBS) $(OBJ_DIR)/fp.o $(OBJ_DIR)/util.o $(OBJ_DIR)/oslo.o $(OBJ_DIR)/main.o -o $(OBJ_DIR)/$@

clean:
	$(RM) $(OBJ_DIR)/*
