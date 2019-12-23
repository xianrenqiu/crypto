# library and include dir
GMSSL_DIR := ../common/ext/gmssl
INC = -I.. -I$(GMSSL_DIR)/include
LIB = -L../src -l:libcrypto_api.a -L$(GMSSL_DIR)/lib -l:libcrypto.a -ldl -lpthread

all : 
	gcc -g -Wall -O0 -o ../crypto_demo $(wildcard demo/*.c) $(LIB) $(INC) -std=gnu99 -w
	gcc -g -Wall -O0 -o ../crypto_tools $(wildcard tools/*.c) $(LIB) $(INC) -std=gnu99  -w

clean:
	rm -f ../crypto_demo ../crypto_tools
