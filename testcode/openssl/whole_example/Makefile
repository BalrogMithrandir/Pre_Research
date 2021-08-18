CC = g++
AR = ar

DEL = rm -f

CFLAGS +=  \
    -Wall -g -O0 -std=c++11 -Wl,-rpath=${ORIGIN}../gmssl_op_x86_64/lib 

BUILD_DIR=.
SRC_DIR=.
SDK_DIR=..

EXTERNAL_LIB_NAME := -lssl \
	-lcrypto


#EXTERNAL_LIB_DIR=/usr/local/ssl/lib
EXTERNAL_LIB_DIR=../gmssl_op_x86_64/lib

CLIENTTARGET=client
SERVERTARGET=server

CLIENTCSRCS := \
	$(SRC_DIR)/client.cpp

SERVERCSRCS := \
	$(SRC_DIR)/server.cpp

CLIENTOBJS := $(CLIENTCSRCS:%.cpp=%.o)
SERVEROBJS := $(SERVERCSRCS:%.cpp=%.o)


INCLUDES := ../gmssl_op_x86_64/include

all: $(CLIENTOBJS) $(SERVEROBJS) $(CLIENTTARGET) $(SERVERTARGET)
$(CLIENTOBJS): %.o: %.cpp
	$(CC) -c -I$(INCLUDES) $(CFLAGS) $^ -o $@
$(SERVEROBJS): %.o: %.cpp
	$(CC) -c -I$(INCLUDES) $(CFLAGS) $^ -o $@

$(CLIENTTARGET): $(CLIENTOBJS)
	$(CC)  -o $(CLIENTTARGET) -I$(INCLUDES) $(CFLAGS) $(CLIENTOBJS) -L$(EXTERNAL_LIB_DIR) $(EXTERNAL_LIB_NAME)

$(SERVERTARGET): $(SERVEROBJS)
	$(CC)  -o $(SERVERTARGET) -I$(INCLUDES) $(CFLAGS) $(SERVEROBJS) -L$(EXTERNAL_LIB_DIR) $(EXTERNAL_LIB_NAME)


clean:
	$(DEL)  $(TARGET) *.o client server
