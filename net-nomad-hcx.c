#include "include/hcxdumptool.h" // static library header

const char* channels[] = {"1a","2a","3a","4a","5a","6a","7a","8a","9a","10a","11a","12a","13a","14a","34b","36b","38b","40b","42b","44b","46b","48b","52b","56b","60b","64b","100b","104b","108b","112b","116b","120b","124b","128b","132b","136b","140b","144b","149b","153b","157b","161b","165b"};

void print_usage(char* name) {
    printf("usage: %s <interface> <target_mac> [channels_to_scan]\n", name);
    printf("   ex: %s wlan1 11:22:33:44:55:66 1a,6a,11a\n", name);
    printf("        o Default channels: 1a,6a,11a\n");
    printf("        o Unsupported channels will be ignored.\n");
    printf("        o Important notice: channel numbers are not unique and\n");
    printf("          it is mandatory to add band information to the channel number (e.g. 12a)\n");
    printf("              band a: NL80211_BAND_2GHZ\n");
    printf("              band b: NL80211_BAND_5GHZ\n");
    printf("              band c: NL80211_BAND_6GHZ\n");
    printf("              band d: NL80211_BAND_60GHZ\n");
    exit(1);
}

int main(int argc, char **argv) {

    char* channel_list;

    // Args

    switch (argc) {
        case 3:
            channel_list = "1a,6a,11a";
            break;
        case 4:
            channel_list = argv[3];
            break;
        default:
            print_usage(argv[0]);
    }

    // Parse Required Args
    char* iname = argv[1];
    char* target_mac = argv[2];

    // Validate Channels
    int len = sizeof(channels)/sizeof(channels[0]);
    char* token;
    char* rest = channel_list;
    char *copy = (char *)malloc(strlen(channel_list) + 1);
    strcpy(copy, channel_list);
    token = strtok(copy, ",");
 
    while (token != NULL) {
        int i;
        bool f = false;
        for(i = 0; i < len; i++) {
            //printf("i: %d, Channels Entry: %s, Token: %s\n", i, channels[i], token);
            if(strcmp(channels[i], token) == 0) {
                f = true;
                break;
            }
        }
        if (!f) {
            printf("%s not a valid channel.\n", token);
            print_usage(argv[0]);
        }
        token = strtok(NULL, ",");
    }

    // Kickoff HCX with our params
    entrypoint(iname, target_mac, channel_list);
}