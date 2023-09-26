#include "include/hcxdumptool.h" // static library header


int main(int argc, char **argv) {
    if(argc != 3) {
        printf("usage: %s <interface> <target_mac>\n", argv[0]);
        exit(1);
    }
    char* iname = argv[1];
    char* target_mac = argv[2];

    entrypoint(iname, target_mac);
}