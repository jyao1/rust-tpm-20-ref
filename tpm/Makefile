LIBC_INC = -I../smallc/include
OPENSSL_INC = -I../openssl/include \
	-I../openssl-stubs/conf-include

DEFINED =
LLVM_TARGET_ARCH = -target x86_64-unknown-windows-gnu
CFLAGS += ${LLVM_TARGET_ARCH} ${DEFINED} ${INCLUDES} \
	-g -Wall -Werror -Wno-empty-body -std=c11 \
	-nostdlib -nostdlibinc -ffreestanding \
	-mno-red-zone -mcmodel=small \
	-fno-builtin -fno-stack-protector

PLATFORM_C := $(wildcard platform/src/*.c) $(wildcard ../openssl-stubs/rand_pool.c)
PLATFORM_H := $(wildcard platform/include/*.h) $(wildcard platform/include/**/*.h)
PLATFORM_OBJ = $(PLATFORM_C:.c=.o)
PLATFORM_INC = -Iplatform/include \
	-Iplatform/include/prototypes
PLATFORM_TARGET = libplatform.a platform.lib
PLATFORM_CFLAGS =

TPM_C := $(wildcard ../ms-tpm-20-ref/TPMCmd/tpm/src/**/*.c) $(wildcard ../ms-tpm-20-ref/TPMCmd/tpm/src/**/**/*.c)
TPM_H := $(wildcard ../ms-tpm-20-ref/TPMCmd/tpm/include/*.h) $(wildcard ../ms-tpm-20-ref/TPMCmd/tpm/include/**/*.h)
TPM_OBJ = $(TPM_C:.c=.o)
TPM_INC = -I../ms-tpm-20-ref/TPMCmd/tpm/include \
	-I../ms-tpm-20-ref/TPMCmd/tpm/include/prototypes
TPM_CONFIG_INCLUDE = -include ./include/TpmProfile.h
TPM_TARGET = libtpm.a tpm.lib
TPM_DEFINED = -DTHIRTY_TWO_BIT -DRADIX_BITS=32 -DCERTIFYX509_DEBUG=NO -DSIMULATION=NO

all: $(PLATFORM_TARGET) $(TPM_TARGET)

$(PLATFORM_TARGET): $(PLATFORM_OBJ)
	$(RM) $@
	$(AR) ru $@ $^

$(PLATFORM_OBJ): %.o: %.c $(PLATFORM_H)
	$(CC) $(TPM_CONFIG_INCLUDE) $(LIBC_INC) $(PLATFORM_INC) $(TPM_INC) $(OPENSSL_INC) $(TPM_DEFINED) $(PLATFORM_CFLAGS) $(CFLAGS) -c -o $@ $<

$(TPM_TARGET): $(TPM_OBJ)
	$(RM) $@
	$(AR) ru $@ $^

$(TPM_OBJ): %.o: %.c $(TPM_H)
	$(CC)  $(TPM_CONFIG_INCLUDE) $(LIBC_INC) $(TPM_INC) $(PLATFORM_INC) $(OPENSSL_INC) $(TPM_DEFINED) $(CFLAGS) -c -o $@ $<

clean: clean_platform clean_tpm

clean_platform:
	$(RM) $(PLATFORM_OBJ) $(PLATFORM_TARGET)
clean_tpm:
	$(RM) $(TPM_OBJ) $(TPM_TARGET)
