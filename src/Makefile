GCC = gcc
LD = ld
AR = ar

GMSSL_DIR := ../common/ext/gmssl

CFLAGS = -g -O0 -Wall -fpic -std=c99 -L$(GMSSL_DIR)/lib -l:libcrypto.a -ldl -lpthread

INC = -I$(GMSSL_DIR)/include -I..

SDK_SRC = $(wildcard *.c)

SDK_OBJ = $(patsubst %.c,%.o,$(SDK_SRC))

.PHONY : all
all: tsr

tsr:$(SDK_OBJ)
	$(LD) -shared -o libcrypto_api.so $(SDK_OBJ)
	${AR} -rc libcrypto_api.a $(SDK_OBJ)

%.o:%.c
	$(GCC) $(CFLAGS) -o $@ -c $< ${INC}

.PHONY : clean

clean:
	@clear;
	@echo
	@echo Delete: Intermediate build files...
	@rm -f *.o *.so *.a
	@echo Delete: ....finished!
	@echo
