all: net-nomad-hcx clean

net-nomad-hcx: net-nomad-hcx.o libhcxdumptool.a
		gcc -Wall -o net-nomad-hcx net-nomad-hcx.c -lhcxdumptool -lpcap -Llib -Iinclude

net-nomad-hcx.o: net-nomad-hcx.c
		gcc -O -c net-nomad-hcx.c

hcxdumptool.o: hcxdumptool.c include/hcxdumptool.h
		gcc -c -Wall -Werror -fPIC hcxdumptool.c

libhcxdumptool.a: hcxdumptool.o
		ar cr lib/libhcxdumptool.a hcxdumptool.o

libs: libhcxdumptool.a

cleanall:
		rm -f net-nomad-hcx *.o libs/*.a *.gch

clean:
		rm -f *.o *.gch