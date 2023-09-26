#include <stdio.h>
#include <pcap.h>

char filter_str[500];

void generate_filter(char *dev, char *addr) {
    
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    
    char filter_exp[125];
    snprintf(filter_exp, sizeof filter_exp, "wlan addr1 %s or wlan addr2 %s or wlan addr3 %s or wlan addr3 ff:ff:ff:ff:ff:ff", addr, addr, addr);
    printf("Filter: %s\n", filter_exp);
    
    bpf_u_int32 subnet_mask, ip;

    if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        printf("Could not open %s - %s\n", dev, error_buffer);
        return 2;
    }
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    struct bpf_insn *insn;
	int i;
	int n = filter.bf_len;
	insn = filter.bf_insns;

    snprintf(filter_str, sizeof filter_str, "%d\n", n);
    for (i = 0; i < n; ++insn, ++i) {
        snprintf(filter_str+strlen(filter_str), sizeof filter_str, "%u %u %u %u\n", insn->code, insn->jt, insn->jf, insn->k);
        //printf("%u %u %u %u\n", insn->code, insn->jt, insn->jf, insn->k);
    }
}

int main(int argc, char **argv) {
    
    if( argc != 3 ) {
        printf("Usage: %s <device> <mac_addr>\n", argv[0]);
        exit(0);
    }
    
    char *dev = argv[1];
    char *addr = argv[2];
    
    printf("Device: %s - Addr: %s\n", dev, addr);
    
    generate_filter(dev , addr);
    printf("\n==========================\n%s\n==========================\n", filter_str);
    
    return 0;
}