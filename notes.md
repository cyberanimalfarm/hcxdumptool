# Notes
#### These notes are rapid references so I could figure out what the fuck I was seeing.


##### wanteventflag
```
// EXIT_ON_SIGTERM 0x01			: 00000001
// EXIT_ON_TOT 0x04				: 00000100
// EXIT_ON_WATCHDOG 0x08		: 00001000
// EXIT_ON_EAPOL_PMKID 0x10		: 00010000
// EXIT_ON_EAPOL_M2 0x20		: 00100000
// EXIT_ON_EAPOL_M3 0x40 		: 01000000
// EXIT_ON_ERROR 0x80 			: 10000000
```


##### aplist_t
```c
typedef struct __attribute__((__packed__))
{
    u64 tsakt; // realtime recieved in nanoseconds
    u64 tshold1; // realtime recieved in nanoseconds
    u64 tsauth; // timestamp of last auth
    u32 count; // count of AP interactions (starts at max, counts down)
    u8 macap[6]; // macaddr we used to interact
    u8 macclient[6]; // client mac we used to interact
    u8 status; // flags (see below)
// status flags
                                // 00011111
#define AP_IN_RANGE 0x01        // 00000001
#define AP_ESSID 0x02           // 00000010
#define AP_BEACON 0x04          // 00000100
#define AP_PROBERESPONSE 0x08   // 00001000
#define AP_EAPOL_M1 0x10        // 00010000
#define AP_EAPOL_M2 0x20        // 00100000
#define AP_EAPOL_M3 0x40        // 01000000
#define AP_PMKID 0x80           // 10000000

#define AP_PMKID_EAPOL 0xc0     // 11000000 - Not Used, potentially to check if we have all PMKID/M3?
#define AP_IN_RANGE_MASK 0xfe   // 11111110 - Resets AP_IN_RANGE
#define AP_IN_RANGE_TOT 120000000000ULL // 120 seconds

    infoelement_t ie; // relevant info elements for reference - see below
} aplist_t;
```

##### clientlist_t
```c
typedef struct __attribute__((__packed__))
{
    u64 tsakt; // realtime recieved in nanoseconds
    u64 tsauth; // timestamp of last auth
    u64 tsassoc; // timestamp last assoc
    u64 tsreassoc; // timestamp last reassoc
    u16 aid; // Association ID
    u8 macclient[6]; // Mac of Client
    u8 macap[6]; // Mac of AP (What we impersonate)
    u8 mic[4]; // Message Integrity Code
    u8 status; // Status Flags - See below
#define CLIENT_EAP_START 0x01 // We have seen a EAP START (for EAP-TLS)
#define CLIENT_EAPOL_M2 0x02 // We have collected a M2 from client (This is the best we can get, as it's unencrypted!)
    u32 count; // Client Interaction Count - starts from max, counts backwards.
    infoelement_t ie; // relevant info elements for reference
} clientlist_t;
```

##### infoelement_t
```c
typedef struct __attribute__((__packed__))
{
    u8 flags; // IE Flags - see below
#define APIE_ESSID 0x0001
#define APGS_CCMP 0x0002
#define APGS_TKIP 0x0004
#define APCS_CCMP 0x0008
#define APCS_TKIP 0x0010
#define APRSNAKM_PSK 0x0020
#define APRSNAKM_PSK256 0x0040
#define APRSNAKM_PSKFT 0x0080
#define APWPAAKM_PSK 0x0100
#define APAKM_MASK 0x01e0
#define AP_MFP 0x0200
    u8 essidlen; // length of ESSID
    u8 essid[ESSID_MAX]; // ESSID
    u16 channel; // Channel
} infoelement_t;
```