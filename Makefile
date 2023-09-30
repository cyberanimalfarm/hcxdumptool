
all: net-nomad-hcx clean

net-nomad-hcx: net-nomad-hcx.o libhcxdumptool.a
		g++ -Wall -o net-nomad-hcx net-nomad-hcx.cpp -lhcxdumptool -lpcap -Llib -Iinclude -lcjson

net-nomad-hcx.o: net-nomad-hcx.cpp
		g++ -O -c net-nomad-hcx.cpp

hcxdumptool.o: hcxdumptool.c include/hcxdumptool.h include/cJSON.h 
		gcc -c -Wall -Werror -fPIC hcxdumptool.c -lcjson -Llib -Iinclude $(pkg-config --cflags libcjson) 

libhcxdumptool.a: hcxdumptool.o
		ar cr lib/libhcxdumptool.a hcxdumptool.o

libs: libhcxdumptool.a

cleanall:
		rm -f net-nomad-hcx *.o libs/*.a *.gch

clean:
		rm -f *.o *.gch
