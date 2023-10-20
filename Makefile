UNAME_M := $(shell uname -m)
	ifeq ($(UNAME_M),x86_64)
		ARCH = x86_64
	endif
	ifeq ($(UNAME_M),aarch64)
		LONG_BIT := $(shell getconf LONG_BIT)
		ifeq ($(LONG_BIT),64)
			ARCH = aarch64
		endif 
		ifeq ($(LONG_BIT),32)
			ARCH = armhf
		endif
	endif

all: net-nomad-hcx clean 
	echo "Build Succeeded"

net-nomad-hcx: net-nomad-hcx.o libhcxdumptool.a libhcxpcapngtool.a
	g++ -w -o net-nomad-hcx_x86_64 net-nomad-hcx.cpp \
	-Llib \
	-L/usr/local/ssl/lib \
	-L/usr/lib/x86_64-linux-gnu \
	-I/usr/local/ssl/include \
	-Iinclude \
	-Ihcxpcapngtool/include/pcapngtool/ \
	-Wl,-Bstatic \
	-lhcxdumptool \
	-lhcxpcapngtool \
	-lssl \
	-lcrypto \
	-lcjson \
	-lfmt \
	-lpcap \
	-ldbus-1 \
	-lz \
	-larchive \
	-Wl,-Bdynamic \
	-lgcc_s \
	-llzma \
	-lxml2 \
	-lbz2 \
	-lnettle \
	-lsystemd \

net-nomad-hcx.o: net-nomad-hcx.cpp
	g++ -O -c net-nomad-hcx.cpp

hcxdumptool.o: hcxdumptool.c include/hcxdumptool.h include/cJSON.h 
	gcc -w -c -fPIC hcxdumptool.c -lcjson -Llib -Iinclude -I/usr/local/include -I/usr/local/include/cjson

libhcxdumptool.a: hcxdumptool.o
	ar cr lib/libhcxdumptool.a hcxdumptool.o

hcxpcapngtool.o: hcxpcapngtool/hcxpcapngtool.c
	gcc -w -c -fPIC hcxpcapngtool/hcxpcapngtool.c -Llib -L/usr/local/lib -L /usr/local/ssl/lib -I/usr/include -Ihcxpcapngtool/include/pcapngtool/ -Ihcxpcapngtool/include -I/usr/local/ssl/include -I/usr/local/include -I/usr/local/include/cjson -lssl -lcrypto -lcjson -lnettle -lxml2 -llzma -lbz2 -lpcap -ldbus-1 -larchive

libhcxpcapngtool.a: hcxpcapngtool.o
	ar cr lib/libhcxpcapngtool.a hcxpcapngtool.o

libs: libhcxdumptool.a libhcxpcapngtool.a

cleanall:
	rm -f net-nomad-hcx *.o lib/*.a *.gch

clean:
	rm -f *.o *.gch