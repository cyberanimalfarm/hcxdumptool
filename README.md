# net-nomad-hcx

A gutted (and combined) hcxdumptool & hcxpcapngtool v6.3.1 that builds into a static object (for including in your project), and also has a C++ starter for you to use.

o Writes data in realtime to stdout in JSON format.
o When capture is complete writes relevant files to disk ready for hashcat.
o Easy to work with as a subprocess.

If you would prefer to just download the pre-compiled binaries, check the Releases for x86_64, armhf, and aarch64 (both build on Rpi).

## Usage + Output

Example Usage:
```
sudo ../net-nomad-hcx_x86_64 panda0 74acb9xxxxxx 40:9b:cd:ab:1a:bc 6c-99-61-db-cb-86 -c 1a,6a,11a
{ 1 }  {--------2---------}  {-3-}   {-----------------------4---------------------}  {-----6----}

1. Run as root
2. The binary... duh
3. The interface to use - must support monitor mode and packet injection, at9k_htc or rt2800 pref.)
4. The targets we want to go after, must include atleast one. All three formats valid.
5. The channels we want to "hop" across. Unsupported channels will be ignored.
*** Important notice: channel numbers are not unique and it is mandatory to add band information to the channel number (e.g. 12a)
    band a: NL80211_BAND_2GHZ
    band b: NL80211_BAND_5GHZ
    band c: NL80211_BAND_6GHZ
    band d: NL80211_BAND_60GHZ
```

Help:
```bash
sudo ../net-nomad-hcx_x86_64 -h                   
WiFi attack tool based on the HCX Dump Tool engine.
Usage:
  NET NOMAD HCX [OPTION...] <interface> <target> <target> <target>...
  -f, --file arg      Path to file containing target MAC addresses, one per line
  -o, --outfile arg   Output filename for results
  -c, --channels arg  Channels Ex: 1a,6a,11a OR [LB/HB/ALL] | Default: 1a,6a,11a
  -n, --notar         Instructs NN to NOT create Tarfile of all output files | Default: false
  -p, --pcapng        Instructs NN to produce PCAP-NG file | Default: false
  -r, --clear         Instructs NN to clear screen before printing a new status. Do not use with jq. | Default: false
  -h, --help          Display Help
```

NOTE: You really probably don't want to scan a lot of channels. This isn't a survey tool, it's a target attack tool. The BPF set by the "targets" will mean that you are likely to not see a lot of packets on other channels because we are literally not seeing anything unless it matches the BPF. This will reduce the number of incoming packets from your target. Use the `LB`, `HB`, and `ALL` options sparingly and only when you absolutely do not know the channel your target will be on.

Output will be a "waterfall" of individual json lines, seperated by a newline, unless the -r/--clear option is specificed. Do not use this options with jq directly without handling an error..

To end collection send a SIGINT (CTRL+C). This will automatically pass the collected data to the pcaptool to produce the output files.

Example output:

First will print the args:

** Made pretty for your viewing pleasure, will not print with newlines.
```json
{
  "ARGS": {
    "interface": "panda0",
    "outfile": "NetNomad-20231006-00-05-40",
    "targets": "74acb9xxxxxx",
    "channels": "6a",
    "tarfile": "true",
    "pcapng": "false",
    "clear": "false"
  }
}
```

Then will print the "status" output: 

** Made pretty for your viewing pleasure, will not print with newlines.
```json
{
  "dumptool": {
    "aplist": [
      {
        "tsakt": 1696564039,
        "tshold1": 1696564033,
        "tsauth": 1696564034,
        "count": 0,
        "macap": "74acb9xxxxxx",
        "macclient": "d48a3bxxxxxx",
        "status": 31,
        "AP_IN_RANGE": true,
        "ESSID_COLLECTED": true,
        "BEACON_COLLECTED": true,
        "PROBE_RESP_COLLECTED": true,
        "EAPOL_M1_COLLECTED": true,
        "EAPOL_M2_COLLECTED": false,
        "EAPOL_M3_COLLECTED": false,
        "PMKID_COLLECTED": false
      }
    ],
    "clientlist": [
      {
        "tsakt": 1696564037,
        "tsauth": 0,
        "tsassoc": 1696564027,
        "tsreassoc": 1696564027,
        "aid": 0,
        "count": 10,
        "macap": "74acb9xxxxxx",
        "macclient": "d48a3bxxxxxx",
        "mic": [
          0,
          0,
          0,
          0
        ],
        "status": 0,
        "EAP_START_COLLECTED": false,
        "ROGUE_M2_COLLECTED": false
      }
    ]
  }
}
```

Finally prints results of collection after you send SIGINT (ctrl+c):
** Made pretty for your viewing pleasure, will not print with newlines.
```json
{
  "pcaptool": {
    "interface_id": 1,
    "raw_packet_count": 31,
    "skipped_packet_count": 0,
    "fcs_frame_count": 0,
    "band24_count": 31,
    "band5_count": 0,
    "band6_count": 0,
    "wds_count": 0,
    "device_info_count": 1,
    "essid_count": 3,
    "beacon_count": 3,
    "beacon_count_24": 3,
    "beacon_count_5": 0,
    "probe_request_undirected_count": 0,
    "probe_request_directed_count": 0,
    "probe_response_count": 3,
    "deauthentication_count": 0,
    "disassociation_count": 0,
    "authentication_count": 3,
    "auth_open_system_count": 3,
    "auth_shared_key_count": 0,
    "association_request_count": 0,
    "username_count": 0,
    "identity_count": 0,
    "eapol_m1_count": 22,
    "eapol_m2_count": 0,
    "eapol_m3_count": 0,
    "eapol_m4_count": 0,
    "eapol_m4_zeroed_count": 0,
    "eapol_mp_count": 0,
    "zeroed_eapol_psk_count": 0,
    "zeroed_eapol_pmk_count": 0,
    "eapol_mp_bestcount": 0,
    "eapol_apless_count": 0,
    "eapol_written_count": 0,
    "eapolnc_written_count": 0,
    "pmkid_best_count": 0,
    "pmkid_rogue_count": 0,
    "pmkid_written_count": 0,
    "pmkid_client_written_count": 0,
    "total_written": 0,
    "timestamp_minimum": "10.04.2023 22:55:32",
    "timestamp_maximum": "10.04.2023 22:55:35",
    "timestamp_total": 3,
    "22000_exported": 0,
    "22000client_exported": 0,
    "essid_exported": 1,
    "identity_exported": 0,
    "username_exported": 0,
    "deviceinfo_exported": 1,
    "pcapng_exported": 0,
    "files_compressed": 1
  }
}
```

Output will ALWAYS be an "ARGS" json object (with the args you used to run the program, including the ones you didn't specify) a waterfall of "dumptool", and then the final "pcaptool" output with the results of your usage.

Errors will also be in JSON format:

```json
{"ERROR":{"message":"Could not open wlan1 - wlan1: No such device exists (SIOCGIFHWADDR: No such device)","fatal":true}}
{"ERROR":{"message":"failed to arm interface","fatal":true}}
{"ERROR":{"message":"Incorrect Magic","fatal":true}}
```

You can see what each key means and how the values are represented here:

[Google Sheets](https://docs.google.com/spreadsheets/d/1_Ztu8rNvnV8Id_MLcIl8FbdCwIjK6nVBU_wC5mD-5xA/edit?usp=sharing)

## Build

#####Depends:
```git 
build-essential
libgcc-10-dev
zlib1g-dev 
checkinstall 
libpcap-dev 
libssl-dev 
libarchive-dev 
libbz2-dev 
liblzma-dev
libxml2-dev
nettle-dev
libdbus-1-dev
libsystemd-dev
cmake
cJSON (https://github.com/DaveGamble/cJSON) Built statically (-DBUILD_SHARED_LIBS=Off flag for cmake)
openssl 3+
```

And maybe some other shit I'm forgetting about?

### Normal Build Instructions: (if you already have openssl 3+)

Tested on Ubunutu 22.04

Instructions:
```bash
sudo apt install -y git build-essential zlib1g-dev checkinstall libpcap-dev libssl-dev libarchive-dev libbz2-dev liblzma-dev cmake libxml2-dev nettle-dev libdbus-1-dev libgcc-10-dev

# Build libfmt statically
cd 
wget https://github.com/fmtlib/fmt/releases/download/10.1.0/fmt-10.1.0.zip
unzip fmt-10.1.0.zip
cd fmt-10.1.0
mkdir build && cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE ..
sudo make install

# Build cJSON
cd
git clone https://github.com/DaveGamble/cJSON
cd cJSON
mkdir build; cd build
cmake .. -DBUILD_SHARED_LIBS=Off
make
sudo make install
make

# Build net-nomad-hcx
git clone <this repo>
cd net-nomad-hcx
make
cp net-nomad-hcx /usr/local/bin # this could be in the Makefile but whatever.
```

### RaspberryPi

From a completely fresh Raspberry Pi OS Bullseye Lite you need to update OpenSSL, build/install cJSON, and build net-nomad-hcx.

Tested on both Raspios Bullseye Lite 32 and 64bit.

Because it's confusing:

RPi 3/4 (and probably 5) will always run a 64bit Kernel. However, the userland can be either 32 or 64 bit. Many utilities will report ONLY the kernel bitness, which may confuse you. You can determine the actual bitness of your userland by running the following command.

```
getconf LONG_BIT
```

Instructions:
```bash
# Install deps
sudo apt install -y git build-essential zlib1g-dev checkinstall libpcap-dev libssl-dev libarchive-dev libbz2-dev liblzma-dev cmake libxml2-dev nettle-dev libdbus-1-dev libsystemd-dev libgcc-10-dev

# Install new openssl
# I understand the OS relies heavily on OpenSSL and updating it COULD fuck up the OS. However, using this method I haven't seen anything get fucked up.
export VER=3.1.3 ##This was the latest stable at the time of writing, as far as I know anything 3+ should be good. Ref: https://www.openssl.org/source/
cd /usr/local/src/
sudo wget https://www.openssl.org/source/openssl-$VER.tar.gz 
sudo tar -xf openssl-$VER.tar.gz
cd openssl-$VER/

# Determine GCC bitness. Basically the Kernel will likely be 64 bit, but userspace could be 32 or 64.
getconf LONG_BIT

# if 64
sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib

# if 32:
sudo ./config linux-armv4 --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib

sudo make # This will take a really long time. Like go to the gym and come back long.
sudo make install # This will take not as long but still a few minutes. Go take your post-gym shower.
sudo bash -c "echo /usr/local/ssl/lib > /etc/ld.so.conf.d/openssl-$VER.conf"
sudo ldconfig -v
sudo mv /usr/bin/openssl /usr/bin/openssl.bak
sudo mv /usr/bin/c_rehash /usr/bin/c_rehash.bak
echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/ssl/bin"' | sudo tee -a /etc/environment
source /etc/environment
echo $PATH
openssl version | grep $VER

# Build libfmt (statically))
cd 
wget https://github.com/fmtlib/fmt/releases/download/10.1.0/fmt-10.1.0.zip
unzip fmt-10.1.0.zip
cd fmt-10.1.0
mkdir build && cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE ..
sudo make install

# Build cJSON (statically)
cd
git clone <this repo>
git clone https://github.com/DaveGamble/cJSON
cd cJSON
mkdir build; cd build
cmake .. -DBUILD_SHARED_LIBS=Off
make
sudo make install

# Build net-nomad-hcx
git clone <this repo>
cd net-nomad-hcx
make
```

### Build Static Libraries Only (for use in your own project)

produces lib/libhcxdumptool.a and lib/libhcxpcapngtool.a

```
make libs
```

### Clean Everything (for rebuild)

```
make cleanall
```

## Hashcat 22000 Format

Example:
```
WPA*02*1709ba709b92c3eb7b662036b02e843c*6c5940096fb6*64cc2edaeb52*6c686c64*ca37bb6be93179b0ce86e0f4e393d742fca6854ace6791f29a7d0c0ec1534086*0103007502010a00000000000000000001f09960e32863aa57ba250769b6e12d959a5a1f1cc8939d6bed4401a16092fa72000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020000*00
```

### Explanation:
```
PMKID Version (01):
WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***MESSAGEPAIR

EAPOL Version (02):
WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL_CLIENT*MESSAGEPAIR
```

### MESSAGE PAIR Values:
```
Byte:    | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
Field:   | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |

Legend:
2,1,0:
000 = M1+M2, EAPOL from M2 (challenge)
001 = M1+M4, EAPOL from M4 if not zeroed (authorized)
010 = M2+M3, EAPOL from M2 (authorized)
011 = M2+M3, EAPOL from M3 (authorized) - unused
100 = M3+M4, EAPOL from M3 (authorized) - unused
101 = M3+M4, EAPOL from M4 if not zeroed (authorized)
3: reserved
4: ap-less attack (set to 1) - no nonce-error-corrections necessary
5: LE router detected (set to 1) - nonce-error-corrections only for LE necessary
6: BE router detected (set to 1) - nonce-error-corrections only for BE necessary
7: not replaycount checked (set to 1) - replaycount not checked, nonce-error-corrections definitely necessary
```

Useful bash to pull the hashes you want out:

### Filter by PMKID:
```
grep 'WPA\*01' hash.hc22000 > pmkid.hc22000
```

### Filter by EAPOL:
```
grep 'WPA\*02' hash.hc22000 > pmkid.hc22000
```

### Filter by Authorized (The PSK provided will be the correct one for the network):
```
grep '2$' hash.hc22000
```

### Filter by Challenge (The PSK provided COULD be incorrect, the network has not validated it yet):
```
grep '0$' hash.hc22000
```

### Filter by MAC:
```
grep '\*112233445566\*'  hash.hc22000 > mac.hc22000
```

### More:
```
#001 = M1+M4, EAPOL from M4 if not zeroed (authorized)
cat hashfile.hc22000 | grep "WPA.02" | grep "1$"

#010 = M2+M3, EAPOL from M2 (authorized)
cat hashfile.hc22000 | grep "WPA.02" | grep "2$"

#101 = M3+M4, EAPOL from M4 if not zeroed (authorized)
cat hashfile.hc22000 | grep "WPA.02" | grep "5$"

# or, if you don't want NC to be in use:

#001 = M1+M4, EAPOL from M4 if not zeroed (authorized)
cat hashfile.hc22000 | grep "WPA.02" | grep "01$"

#010 = M2+M3, EAPOL from M2 (authorized)
cat hashfile.hc22000 | grep "WPA.02" | grep "02$"

#101 = M3+M4, EAPOL from M4 if not zeroed (authorized)
cat hashfile.hc22000 | grep "WPA.02" | grep "05$"
```


## Important Notes

```
Every converted hash should be a valid hash (depending on the quality of the dump tool handling possible packet loss and the conversion tool regarding EAPOL TIME OUT, detecting NC, evaluation RC). The PSK from this hash is recoverable, but it may not belong to your target network if it is converted from M1M2.

Overview of valid MESSAGE PAIRs belonging to the same AUTHENTICATION SEQUENCE:
M1M2 = challenge and RC on M1 and M2 is the same
M2M3 = authenticated (by AP) and RC of M3 = RC M2 +1
M3M4 = authenticated (by CLIENT) and RC on M3 and M4 are the same
M1M4 = authenticated (by CLIENT) and RC of M1 = RC M4 +1

Example of invalid MESSAGE PAIRs (NC not possible = PSK not recoverable):
M1/RC1 M2/RC9
M2/RC3 M3/RC14

Example of invalid MESSAGE PAIRs that can be converted to valid MESSAGE PAIRS (NC possible = PSK recoverable) by hashcat default NC option (8):
M1/RC1 M2/RC3
M2/RC3 M3/RC5

It is not mandatory that they belong to the same AUTHENTICATION sequence, as long as NC is possible.

State of the art attack tools should detect a packet loss and request the packet again. Also they shouldn't run excessive deauthentications/disassociations which cause an AP to reset its EAPOL timers, counters and ANONCE or to start a new AUTHENTICATION sequence.
State of the art conversion tools should detect if NC is possible or not.

BTW3 (experienced users):
The most important MESSAGE PAIR is M1M2ROGUE coming from hcxdumptool/hcxlabtool attack against a weak CLIENT. In combination with hcxpcapngtool --all and -E it will give useful information about the wpa_supplicant.conf entries of the CLIENT.

Legend:
RC = replaycount
NC = nonce error correction on BE and LE routers
BE = big endian
LE = low endian
M1 = EAPOL message 1 (AP) of 4way handshake
M2 = EAPOL message 2 (CLIENT) of 4way handshake
M3 = EAPOL message 3 (AP) of 4way handshake
M4 = EAPOL message 4 (CLIENT) of 4way handshake (useless if SNONCE is zeroed)
ROGUE = coming from hcxdumptool/hcxlabtool attack
PSK = pre-shared key (password of the NETWORK)
```

## Details
--------------

Because people still want to use aircrack-ng for some reason, here's a post written by the HCX author:

```
There is a huge difference between hcxdumptool/hcxtools and other WiFi attack tools. Many options may look similar, but the engine behind is completely different.

hcxdumptool is interacting with the target. If the target is an AP that include all CLIENTs of this NETWORK. As a cause if this, the DEAUTHENTICATION process is not static. hcxdumptool use more than one DEAUTHENTICATION code and it switches from DEAUTHENTICATION to DISASSOCIATION depending on the state of the target. This goes so far that it use different reason codes for the AP and the CLIENTs. You can override this as you already mentioned (--reason_code).

But let me start with the implemented attack vectors that run simultaneously:

BEACON spoofing
PROBERESPONSE spoofing
PROBEREQUEST (to get additional information that is not present in a BEACON)
AUTHENTICATION attack (to prepare one of the following attacks)
ASSOCIATION attack (e.g. to retrieve a PMKID)
REASSOCIATION attack (e.g. to retrieve a PMKID or to downgrade an AUTHENTICATION state)
M2 attack (to retrieve CLIENT NONCE and MIC)
M4 attack (to make sure we got an entire valid handshake or to prevent connections)
PS-POLL (to downgrade an AUTHENTICATION state)
EAP attack (to retrieve an EAP-ID)
DEAUTHENTICATON / DISASSOCIATION attack

On some attacks it make sense to disable them by a single command (e.g. --disable_deauthentication).

Other attacks are grouped and it only make sense to deactivate the entire group (--disable_client_attacks).

Or if an AP is able to detect attacks against it, it may be useful to run attacks only against the CLIENTs (--disable_ap_attacks).

The same applies if the CLIENT is in the range of hcxdumptool but the AP not.

The first step is always to run a rca scan, to find out if the target is in range and to get some additional information, eg. AKM (authentication key management) of the target

Requesting the AKM of a CLIENT is not necessary, because it always announce it in its ASSOCIATIONREQUEST.

Take a look at the RSN IE_TAG field (by Wireshark or by tshark)

Code:
RSN Capabilities: 0x00c0
    .... .... .... ...0 = RSN Pre-Auth capabilities: Transmitter does not support pre-authentication
    .... .... .... ..0. = RSN No Pairwise capabilities: Transmitter can support WEP default key 0 simultaneously with Pairwise key
    .... .... .... 00.. = RSN PTKSA Replay Counter capabilities: 1 replay counter per PTKSA/GTKSA/STAKeySA (0x0)
    .... .... ..00 .... = RSN GTKSA Replay Counter capabilities: 1 replay counter per PTKSA/GTKSA/STAKeySA (0x0)
    .... .... .1.. .... = Management Frame Protection Required: True
    .... .... 1... .... = Management Frame Protection Capable: True
    .... ...0 .... .... = Joint Multi-band RSNA: False
    .... ..0. .... .... = PeerKey Enabled: False
    ..0. .... .... .... = Extended Key ID for Individually Addressed Frames: Not supported

Management frame protection is enabled and it is absolutely useless to inject DEAUTHENTICATION frames or DISASSOCIATION frames. As long as the target is not downgraded, it will only jam the channel. To avoid this, use e.g. --disable_deauthentication.

Please note:

The BEACON IE_TAGs give an overview of the capabilities of an AP.
The PROBERESPONSE IE_TAGs show all supported capabilities.
But only the ASSOCIATIONREQUEST/REASSOCIATIONREQUEST IE_TAGs give an information about the capabilities that are in use on the following connection (that include the ESSID).
The IE_TAGs of this frames may differ and it is mandatory to get the last one (instead of only the first one in the BEACON).

Ignoring this kind of frames can lead to an issue like this one:
https://github.com/kismetwireless/kismet/issues/419

Luckily there are some frames that can't be protected (ASSOCIATIONREQUEST, REASSOCIATIONREQUEST, PS POLL). Now hcxdumptool try to downgrade the AUTHENTICATION state of the target (using this CLASS 3 or CLASS 4 frames) to a state that will allow to throw off the CLIENTs. If successful, mostly the AP will do this job for us (you noticed that the CLIENTs are disconnected even though you have disabled DEAUTHENTICATIONs). That include a WPA3 connection, too. Now, if CLIENT attacks are not disabled, the CLIENT first try to connect to hcxdumptool and we can retrieve its M2. Than the CLIENT will try to connect to its AP and we can get M1M2M3M4. For both cases there is an option to disable this behavior.

Some of the attack vectors are extremely aggressive (e.g. M4 attack), because they are able to prevent that the CLIENT can reconnect. This attack vector is also usable to fool a user, because (depending on the reason code) he have to type his PSK again, and again, and again... (for all eternity or until --stop_client_m2_attacks= is reached).
The M2 attack vector e.g. is able to retrieve more than one PSK from the CLIENT.
The EAP attack vector is able to retrieve an EAP-ID from the target (that can be the IMEI of a mobile phone).

BPF code is really powerful and it allow you to control hcxdumptool behavior completely. It allow to attack/protect an entire NETWORK (addr3), to attack frames coming from a target (addr2), to attack frames going to a target (addr1) or any combination of this. Also it allow to attack/protect all kinds of frames. A combination of targets and frames is possible. This will act as a scalpel. Additional it is possible to use all options, the soft filter and BPC in combination.

By default, most of the options are activated. Only with activated options hcxdumptool is able to interact with the target and to choose that attack vector which is the best to retrieve the hash in a short time. How long it take or when a CLIENT is allowed to connect again , can be controlled via options, too: --stop_ap_attacks= or --stop_client_m2_attacks= or a combination of that.

If you choose --disable_deauthentication only, all remaining attack vectors are still active (and they are much more powerful than a stupid deauthentication attack). A connected CLIENT will be downgraded, BEACONs and PROBERESONSES are spoofed and hcxdumptool respond to all CLIENTs. As a result to this response every CLIENT will leave its associated AP and connect to hcxdumptool.

```