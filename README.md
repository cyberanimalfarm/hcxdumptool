net-nomad-hcx
==============

A gutted HCXDUMPTOOL v6.3.1 that builds into a static object. 

net-nomad-hcx is a controller program used to demonstrate the use-case.


Install
--------------

```
make
```

Clean Up
--------------

```
make cleanall
```

Details
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