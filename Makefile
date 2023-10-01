
all: net-nomad-hcx clean

net-nomad-hcx: net-nomad-hcx.o libhcxdumptool.a libhcxpcapngtool.a
		g++ -o net-nomad-hcx net-nomad-hcx.cpp -Llib -Iinclude -Ihcxpcapngtool/include/pcapngtool/ -lhcxdumptool -lhcxpcapngtool -lssl -lcrypto -lz -lpcap -lcjson

net-nomad-hcx.o: net-nomad-hcx.cpp
		g++ -O -c net-nomad-hcx.cpp

hcxdumptool.o: hcxdumptool.c include/hcxdumptool.h include/cJSON.h 
		gcc -c -fPIC hcxdumptool.c -lcjson -Llib -Iinclude $(pkg-config --cflags libcjson) 

libhcxdumptool.a: hcxdumptool.o
		ar cr lib/libhcxdumptool.a hcxdumptool.o

hcxpcapngtool.o: hcxpcapngtool/hcxpcapngtool.c
	gcc -c -fPIC hcxpcapngtool/hcxpcapngtool.c -I/usr/include -Lhcxpcapngtool/lib -Ihcxpcapngtool/include/pcapngtool/ -Ihcxpcapngtool/include -lssl -lcrypto -lz 

libhcxpcapngtool.a: hcxpcapngtool.o
		ar cr lib/libhcxpcapngtool.a hcxpcapngtool.o

libs: libhcxdumptool.a libhcxpcapngtool.a

cleanall:
		rm -f net-nomad-hcx *.o lib/*.a *.gch

clean:
		rm -f *.o *.gch
