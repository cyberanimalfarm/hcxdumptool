#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/types.h>

#include <archive.h>
#include <archive_entry.h>

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

#include "include/pcapngtool/hcxpcapngtool.h"
#include "include/ieee80211.c"
#include "include/strings.c"
#include "include/byteops.c"
#include "include/fileops.c"
#include "include/hashops.c"
#include "include/pcap.c"
#include "include/gzops.c"
#include "include/cJSON.h"

/*===========================================================================*/
struct hccap_s
{
	char essid[36];
	unsigned char ap[6];
	unsigned char client[6];
	unsigned char snonce[32];
	unsigned char anonce[32];
	unsigned char eapol[256];
	int eapol_size;
	int keyver;
	unsigned char keymic[16];
};
typedef struct hccap_s hccap_t;
#define HCCAP_SIZE (sizeof(hccap_t))
/*===========================================================================*/
struct hccapx_s
{
	uint32_t signature;
#define HCCAPX_SIGNATURE 0x58504348
	uint32_t version;
#define HCCAPX_VERSION 4
	uint8_t message_pair;
	uint8_t essid_len;
	uint8_t essid[32];
	uint8_t keyver;
	uint8_t keymic[16];
	uint8_t ap[6];
	uint8_t anonce[32];
	uint8_t client[6];
	uint8_t snonce[32];
	uint16_t eapol_len;
	uint8_t eapol[256];
} __attribute__((packed));
typedef struct hccapx_s hccapx_t;
#define HCCAPX_SIZE (sizeof(hccapx_t))
/*===========================================================================*/
/*===========================================================================*/
/* global var */
static EVP_MAC *hmac;
static EVP_MAC *cmac;
static EVP_MAC_CTX *ctxhmac;
static EVP_MAC_CTX *ctxcmac;
static OSSL_PARAM paramsmd5[3];
static OSSL_PARAM paramssha1[3];
static OSSL_PARAM paramssha256[3];
static OSSL_PARAM paramsaes128[3];

static size_t magicblockcount;
static maclist2_t *aplist, *aplistptr;
static messagelist_t *messagelist;
static handshakelist_t *handshakelist, *handshakelistptr;
static pmkidlist_t *pmkidlist, *pmkidlistptr;
static eapmd5msglist_t *eapmd5msglist;
static eapmd5hashlist_t *eapmd5hashlist, *eapmd5hashlistptr;
static eapleaphashlist_t *eapleaphashlist, *eapleaphashlistptr;
static eapleapmsglist_t *eapleapmsglist;
static eapmschapv2hashlist_t *eapmschapv2hashlist, *eapmschapv2hashlistptr;
static eapmschapv2msglist_t *eapmschapv2msglist;
static tacacsplist_t *tacacsplist, *tacacsplistptr;

static char *jtrbasenamedeprecated;

static FILE *fh_pmkideapol;
static FILE *fh_pmkideapolclient;
static FILE *fh_essid;
static FILE *fh_deviceinfo;
static FILE *fh_identity;
static FILE *fh_username;

static int maclistmax;
static int handshakelistmax;
static int pmkidlistmax;
static int eapmd5hashlistmax;
static int eapleaphashlistmax;
static int eapmschapv2hashlistmax;
static int tacacsplistmax;
static int fd_pcap;
static bool clearScreen;

static int gzipstat;
static int pcapngstat;
static int capstat;

static int endianness;
static uint16_t versionmajor;
static uint16_t versionminor;

static int opensslversionmajor;
static int opensslversionminor;

static uint32_t iface;
static uint32_t dltlinktype[MAX_INTERFACE_ID + 1];
static uint32_t timeresolval[MAX_INTERFACE_ID + 1];

static long int radiotaperrorcount;

static long int nmeacount;
static long int nmeaerrorcount;
static long int rawpacketcount;
static long int pcapreaderrors;
static long int skippedpacketcount;
static long int zeroedtimestampcount;
static long int fcsframecount;
static long int band24count;
static long int band5count;
static long int band6count;
static long int wdscount;
static long int actioncount;
static long int actionessidcount;
static long int awdlcount;
static long int beaconcount;
static long int beaconssidunsetcount;
static long int beaconssidzeroedcount;
static long int beaconssidoversizedcount;
static long int beaconhcxcount;
static long int beaconerrorcount;
static long int broadcastmacerrorcount;
static long int pagcount;
static long int proberesponsecount;
static long int proberesponsessidunsetcount;
static long int proberesponsessidzeroedcount;
static long int proberequestundirectedcount;
static long int proberequestdirectedcount;
static long int mgtreservedcount;
static long int deauthenticationcount;
static long int disassociationcount;
static long int authenticationcount;
static long int authopensystemcount;
static long int authseacount;
static long int authsharedkeycount;
static long int authfbtcount;
static long int authfilscount;
static long int authfilspfs;
static long int authfilspkcount;
static long int authnetworkeapcount;
static long int authunknowncount;
static long int associationrequestcount;
static long int associationrequestpskcount;
static long int associationrequestftpskcount;
static long int associationrequestpsk256count;
static long int associationrequestsae256count;
static long int associationrequestsae384bcount;
static long int associationrequestowecount;
static long int reassociationrequestcount;
static long int reassociationrequestpskcount;
static long int reassociationrequestftpskcount;
static long int reassociationrequestpsk256count;
static long int reassociationrequestsae256count;
static long int reassociationrequestsae384bcount;
static long int reassociationrequestowecount;
static long int ipv4count;
static long int icmp4count;
static long int ipv6count;
static long int icmp6count;
static long int tcpcount;
static long int udpcount;
static long int grecount;
static long int protochapcount;
static long int protochapreqcount;
static long int protochaprespcount;
static long int protochapsuccesscount;
static long int protopapcount;
static long int tacacspcount;
static long int tacacsp2count;
static long int tacacsp3count;
static long int tacacspwrittencount;
static long int wepenccount;
static long int wpaenccount;
static long int eapcount;
static long int eapsimcount;
static long int eapakacount;
static long int eappeapcount;
static long int eapmd5count;
static long int eapmd5hashcount;
static long int eapleapcount;
static long int eapleaphashcount;
static long int eapmschapv2count;
static long int eapmschapv2hashcount;
static long int eaptlscount;
static long int eapexpandedcount;
static long int eapidcount;
static long int eapcodereqcount;
static long int eapcoderespcount;
static long int radiusrequestcount;
static long int radiuschallengecount;
static long int radiusacceptcount;
static long int radiusrejectcount;
static long int zeroedpmkidpskcount;
static long int zeroedpmkidpmkcount;
static long int zeroedeapolpskcount;
static long int zeroedeapolpmkcount;
static long int pmkidcount;
static long int pmkidbestcount;
static long int pmkidroguecount;
static long int pmkiduselesscount;
static long int pmkidfaultycount;
static long int pmkidakmcount;
static long int pmkidwrittenhcount;
static long int pmkidclientwrittenhcount;
static long int pmkidwrittenjcountdeprecated;
static long int pmkidwrittencountdeprecated;
static long int eapolrc4count;
static long int eapolrsncount;
static long int eapolwpacount;
static long int eapolmsgcount;
static long int eapolnccount;
static long int eapolmsgerrorcount;
static long int eapolmsgtimestamperrorcount;
static long int eapolmpcount;
static long int eapolmpbestcount;
static long int eapolm1count;
static long int eapolm1kdv0count;
static long int eapolm1ancount;
static long int eapolm1errorcount;
static long int eapolm2count;
static long int eapolm2kdv0count;
static long int eapolm2ftpskcount;
static long int eapolm2errorcount;
static long int eapolm3count;
static long int eapolm3kdv0count;
static long int eapolm3errorcount;
static long int eapolm4count;
static long int eapolm4zeroedcount;
static long int eapolm4kdv0count;
static long int eapolm4errorcount;
static long int eapolwrittencount;
static long int eapolncwrittencount;
static long int eapolaplesscount;
static long int eapolwrittenjcountdeprecated;
static long int eapolwrittenhcpxcountdeprecated;
static long int eapolncwrittenhcpxcountdeprecated;
static long int eapolwrittenhcpcountdeprecated;
static long int eapolm12e2count;
static long int eapolm14e4count;
static long int eapolm32e2count;
static long int eapolm32e3count;
static long int eapolm34e3count;
static long int eapolm34e4count;
static long int eapmd5writtencount;
static long int eapmd5johnwrittencount;
static long int eapleapwrittencount;
static long int eapmschapv2writtencount;
static long int identitycount;
static long int usernamecount;

static uint64_t rcgapmax;

static long int taglenerrorcount;
static long int essidcount;
static long int essiderrorcount;
static long int deviceinfocount;
static long int sequenceerrorcount;
static long int essiddupemax;

static long int malformedcount;

static uint64_t timestampstart;
static uint64_t timestampmin;
static uint64_t timestampmax;
static uint64_t eaptimegapmax;
static uint64_t captimestampold;

static uint64_t eapoltimeoutvalue;
static uint64_t ncvalue;
static int essidsvalue;

static uint16_t frequency;

static int nmealen;

static bool addtimestampflag;
static bool ignoreieflag;
static bool donotcleanflag;
static bool ancientdumpfileformat;
static bool radiotappresent;
static bool ieee80211flag;

static bool pmkidfile = false;
static bool pmkidclientfile = false;
static bool essidfile = false;
static bool identityfile = false;
static bool usernamefile = false;
static bool deviceinfofile = false;
static bool argsfile = false;

static bool data_compressed = false;
static bool pcapng_written = false;

static const uint8_t fakenonce1[] =
	{
		0x07, 0xbc, 0x92, 0xea, 0x2f, 0x5a, 0x1e, 0xe2, 0x54, 0xf6, 0xb1, 0xb7, 0xe0, 0xaa, 0xd3, 0x53,
		0xf4, 0x5b, 0x0a, 0xac, 0xf9, 0xc9, 0x90, 0x2f, 0x90, 0xd8, 0x78, 0x80, 0xb7, 0x03, 0x0a, 0x20};

static const uint8_t fakenonce2[] =
	{
		0x95, 0x30, 0xd1, 0xc7, 0xc3, 0x55, 0xb9, 0xab, 0xe6, 0x83, 0xd6, 0xf3, 0x7e, 0xcb, 0x78, 0x02,
		0x75, 0x1f, 0x53, 0xcc, 0xb5, 0x81, 0xd1, 0x52, 0x3b, 0xb4, 0xba, 0xad, 0x23, 0xab, 0x01, 0x07};

static char rssi;
static int interfacechannel;
static uint8_t myaktap[6];
static uint8_t myaktclient[6];
static uint8_t myaktanonce[32];
static uint8_t myaktsnonce[32];
static uint64_t myaktreplaycount;

static char pcapnghwinfo[OPTIONLEN_MAX];
static char pcapngosinfo[OPTIONLEN_MAX];
static char pcapngapplinfo[OPTIONLEN_MAX];
static char pcapngoptioninfo[OPTIONLEN_MAX];
static char pcapngweakcandidate[OPTIONLEN_MAX];
static uint8_t pcapngdeviceinfo[6];
static uint8_t pcapngtimeresolution;
static char nmeasentence[OPTIONLEN_MAX];
static char gpwplold[OPTIONLEN_MAX];

static char zeroedpsk[8];
static uint8_t zeroedpmk[32];
static uint8_t calculatedpmk[32];

static uint16_t usedfrequency[0xffff];

static uint8_t beaconchannel[CHANNEL_MAX];
/*===========================================================================*/

static void closelists(void)
{
	if (aplist != NULL)
		free(aplist);
	if (messagelist != NULL)
		free(messagelist);
	if (handshakelist != NULL)
		free(handshakelist);
	if (pmkidlist != NULL)
		free(pmkidlist);
	if (eapmd5msglist != NULL)
		free(eapmd5msglist);
	if (eapmd5hashlist != NULL)
		free(eapmd5hashlist);
	if (eapleapmsglist != NULL)
		free(eapleapmsglist);
	if (eapleaphashlist != NULL)
		free(eapleaphashlist);
	if (eapmschapv2msglist != NULL)
		free(eapmschapv2msglist);
	if (eapmschapv2hashlist != NULL)
		free(eapmschapv2hashlist);
	if (tacacsplist != NULL)
		free(tacacsplist);
	return;
}
/*===========================================================================*/
static bool initlists(void)
{
	static const char nastring[] = {"N/A"};

	maclistmax = MACLIST2_MAX;
	if ((aplist = (maclist2_t *)calloc((maclistmax + 1), MACLIST_SIZE2)) == NULL)
		return false;
	aplistptr = aplist;

	if ((messagelist = (messagelist_t *)calloc((MESSAGELIST_MAX + 1), MESSAGELIST_SIZE)) == NULL)
		return false;

	handshakelistmax = HANDSHAKELIST_MAX;
	if ((handshakelist = (handshakelist_t *)calloc((handshakelistmax + 1), HANDSHAKELIST_SIZE)) == NULL)
		return false;
	handshakelistptr = handshakelist;

	pmkidlistmax = PMKIDLIST_MAX;
	if ((pmkidlist = (pmkidlist_t *)calloc((pmkidlistmax + 1), PMKIDLIST_SIZE)) == NULL)
		return false;
	pmkidlistptr = pmkidlist;

	if ((eapmd5msglist = (eapmd5msglist_t *)calloc((EAPMD5MSGLIST_MAX + 1), EAPMD5MSGLIST_SIZE)) == NULL)
		return false;

	eapmd5hashlistmax = EAPMD5HASHLIST_MAX;
	if ((eapmd5hashlist = (eapmd5hashlist_t *)calloc((eapmd5hashlistmax + 1), EAPMD5HASHLIST_SIZE)) == NULL)
		return false;
	eapmd5hashlistptr = eapmd5hashlist;

	if ((eapleapmsglist = (eapleapmsglist_t *)calloc((EAPLEAPMSGLIST_MAX + 1), EAPLEAPMSGLIST_SIZE)) == NULL)
		return false;

	eapleaphashlistmax = EAPLEAPHASHLIST_MAX;
	if ((eapleaphashlist = (eapleaphashlist_t *)calloc((eapleaphashlistmax + 1), EAPLEAPHASHLIST_SIZE)) == NULL)
		return false;
	eapleaphashlistptr = eapleaphashlist;

	if ((eapmschapv2msglist = (eapmschapv2msglist_t *)calloc((EAPMSCHAPV2MSGLIST_MAX + 1), EAPMSCHAPV2MSGLIST_SIZE)) == NULL)
		return false;

	eapmschapv2hashlistmax = EAPMSCHAPV2HASHLIST_MAX;
	if ((eapmschapv2hashlist = (eapmschapv2hashlist_t *)calloc((eapmschapv2hashlistmax + 1), EAPMSCHAPV2HASHLIST_SIZE)) == NULL)
		return false;
	eapmschapv2hashlistptr = eapmschapv2hashlist;

	tacacsplistmax = TACACSPLIST_MAX;
	if ((tacacsplist = (tacacsplist_t *)calloc((TACACSPLIST_MAX + 1), TACACSPLIST_SIZE)) == NULL)
		return false;
	tacacsplistptr = tacacsplist;

	memset(&pcapnghwinfo, 0, OPTIONLEN_MAX);
	memset(&pcapngosinfo, 0, OPTIONLEN_MAX);
	memset(&pcapngapplinfo, 0, OPTIONLEN_MAX);
	memset(&pcapngoptioninfo, 0, OPTIONLEN_MAX);
	memset(&pcapngweakcandidate, 0, OPTIONLEN_MAX);
	memset(&pcapngdeviceinfo, 0, 6);
	pcapngtimeresolution = TSRESOL_USEC;
	memset(&myaktap, 0, 6);
	memset(&myaktclient, 0, 6);
	memset(&nmeasentence, 0, OPTIONLEN_MAX);
	memset(&gpwplold, 0, OPTIONLEN_MAX);

	memcpy(&pcapnghwinfo, nastring, 3);
	memcpy(&pcapngosinfo, nastring, 3);
	memcpy(&pcapngapplinfo, nastring, 3);
	memcpy(&pcapngoptioninfo, nastring, 3);
	memcpy(&pcapngweakcandidate, nastring, 3);

	ieee80211flag = false;

	radiotaperrorcount = 0;
	nmeacount = 0;
	nmeaerrorcount = 0;
	endianness = 0;
	rawpacketcount = 0;
	pcapreaderrors = 0;
	skippedpacketcount = 0;
	zeroedtimestampcount = 0;
	fcsframecount = 0;
	band24count = 0;
	band5count = 0;
	band6count = 0;
	wdscount = 0;
	actioncount = 0;
	actionessidcount = 0;
	awdlcount = 0;
	beaconcount = 0;
	beaconssidunsetcount = 0;
	beaconssidzeroedcount = 0;
	beaconssidoversizedcount = 0;
	beaconhcxcount = 0;
	beaconerrorcount = 0;
	broadcastmacerrorcount = 0;
	pagcount = 0;
	proberesponsecount = 0;
	proberesponsessidunsetcount = 0;
	proberesponsessidzeroedcount = 0;
	proberequestundirectedcount = 0;
	proberequestdirectedcount = 0;
	mgtreservedcount = 0;
	deauthenticationcount = 0;
	disassociationcount = 0;
	authenticationcount = 0;
	authopensystemcount = 0;
	authseacount = 0;
	authsharedkeycount = 0;
	authfbtcount = 0;
	authfilscount = 0;
	authfilspfs = 0;
	authfilspkcount = 0;
	authnetworkeapcount = 0;
	authunknowncount = 0;
	associationrequestcount = 0;
	associationrequestpskcount = 0;
	associationrequestftpskcount = 0;
	associationrequestpsk256count = 0;
	associationrequestsae256count = 0;
	associationrequestsae384bcount = 0;
	associationrequestowecount = 0;
	reassociationrequestcount = 0;
	reassociationrequestpskcount = 0;
	reassociationrequestpsk256count = 0;
	reassociationrequestsae256count = 0;
	reassociationrequestsae384bcount = 0;
	reassociationrequestowecount = 0;
	ipv4count = 0;
	icmp4count = 0;
	ipv6count = 0;
	icmp6count = 0;
	tcpcount = 0;
	udpcount = 0;
	grecount = 0;
	protochapcount = 0;
	protochapreqcount = 0;
	protochaprespcount = 0;
	protochapsuccesscount = 0;
	protopapcount = 0;
	tacacspcount = 0;
	tacacsp2count = 0;
	tacacsp3count = 0;
	tacacspwrittencount = 0;
	wepenccount = 0;
	wpaenccount = 0;
	eapcount = 0;
	eapsimcount = 0;
	eapakacount = 0;
	eappeapcount = 0;
	eapmd5count = 0;
	eapmd5hashcount = 0;
	eapleapcount = 0;
	eapleaphashcount = 0;
	eapmschapv2count = 0;
	eapmschapv2hashcount = 0;
	eaptlscount = 0;
	eapexpandedcount = 0;
	eapidcount = 0;
	eapcodereqcount = 0;
	eapcoderespcount = 0;
	radiusrequestcount = 0;
	radiuschallengecount = 0;
	radiusacceptcount = 0;
	radiusrejectcount = 0;
	zeroedpmkidpskcount = 0;
	zeroedpmkidpmkcount = 0;
	zeroedeapolpskcount = 0;
	zeroedeapolpmkcount = 0;
	pmkidcount = 0;
	pmkidbestcount = 0;
	pmkidroguecount = 0;
	pmkiduselesscount = 0;
	pmkidfaultycount = 0;
	pmkidakmcount = 0;
	pmkidwrittenhcount = 0;
	pmkidclientwrittenhcount = 0;
	eapolwrittenjcountdeprecated = 0;
	pmkidwrittenjcountdeprecated = 0;
	pmkidwrittencountdeprecated = 0;
	eapolrc4count = 0;
	eapolrsncount = 0;
	eapolwpacount = 0;
	eapolmsgcount = 0;
	eapolnccount = 0;
	eapolmsgerrorcount = 0;
	eapolmsgtimestamperrorcount = 0;
	eapolmpbestcount = 0;
	eapolmpcount = 0;
	eapolm1count = 0;
	eapolm1kdv0count = 0;
	eapolm1ancount = 0;
	eapolm1errorcount = 0;
	eapolm2count = 0;
	eapolm2kdv0count = 0;
	eapolm2ftpskcount = 0;
	eapolm2errorcount = 0;
	eapolm3count = 0;
	eapolm3kdv0count = 0;
	eapolm3errorcount = 0;
	eapolm4count = 0;
	eapolm4zeroedcount = 0;
	eapolm4kdv0count = 0;
	eapolm4errorcount = 0;
	eapolwrittencount = 0;
	eapolncwrittencount = 0;
	eapolaplesscount = 0;
	eapolwrittenjcountdeprecated = 0;
	eapolwrittenhcpxcountdeprecated = 0;
	eapolwrittenhcpcountdeprecated = 0;
	eapolm12e2count = 0;
	eapolm14e4count = 0;
	eapolm32e2count = 0;
	eapolm32e3count = 0;
	eapolm34e3count = 0;
	eapolm34e4count = 0;
	eapmd5writtencount = 0;
	eapmd5johnwrittencount = 0;
	eapleapwrittencount = 0;
	eapmschapv2writtencount = 0;
	identitycount = 0;
	usernamecount = 0;
	taglenerrorcount = 0;
	essidcount = 0;
	essiderrorcount = 0;
	deviceinfocount = 0;
	sequenceerrorcount = 0;
	essiddupemax = 0;
	rcgapmax = 0;
	eaptimegapmax = 0;
	malformedcount = 0;
	timestampmin = 0;
	timestampmax = 0;
	timestampstart = 0;
	captimestampold = 0;

	memset(&zeroedpsk, 0, 8);
	memset(&zeroedpmk, 0, 32);
	memset(&beaconchannel, 0, sizeof(beaconchannel));

	memset(&usedfrequency, 0, sizeof(usedfrequency));
	return true;
}
/*===========================================================================*/

/*===========================================================================*/
static void outputwordlists(void)
{
	static int wecl;
	static maclist2_t *pointermac, *pointermacold;

	pointermacold = NULL;
	qsort(aplist, aplistptr - aplist, MACLIST_SIZE2, sort_maclist_by_essidlen);
	wecl = strlen(pcapngweakcandidate);
	if ((wecl > 0) && (wecl < 64) && (strcmp(pcapngweakcandidate, "N/A") != 0))
	{
		if (fh_essid != NULL)
			fprintf(fh_essid, "%s\n", pcapngweakcandidate);
	}
	for (pointermac = aplist; pointermac < aplistptr; pointermac++)
	{
		if ((pointermacold != NULL) && (pointermac->essidlen == pointermacold->essidlen))
		{
			if (memcmp(pointermac->essid, pointermacold->essid, pointermac->essidlen) == 0)
				continue;
		}
		if (fh_essid != NULL)
			fwriteessidstr(pointermac->essidlen, pointermac->essid, fh_essid);
		essidcount++;
		pointermacold = pointermac;
	}
	return;
}
/*===========================================================================*/
static void outputdeviceinfolist(void)
{
	static int p;
	static maclist2_t *pointermac;

	if (fh_deviceinfo == NULL)
		return;
	qsort(aplist, aplistptr - aplist, MACLIST_SIZE2, sort_maclist_by_manufacturer);
	for (pointermac = aplist; pointermac < aplistptr; pointermac++)
	{
		if ((pointermac->manufacturerlen == 0) && (pointermac->modellen == 0) && (pointermac->serialnumberlen == 0) && (pointermac->devicenamelen == 0) && (pointermac->enrolleelen == 0))
			continue;
		if ((pointermac->manufacturer[0] == 0) && (pointermac->model[0] == 0) && (pointermac->serialnumber[0] == 0) && (pointermac->devicename[0] == 0))
			continue;
		for (p = 0; p < 6; p++)
			fprintf(fh_deviceinfo, "%02x", pointermac->addr[p]);
		fwritedeviceinfostr(pointermac->manufacturerlen, pointermac->manufacturer, fh_deviceinfo);
		fwritedeviceinfostr(pointermac->modellen, pointermac->model, fh_deviceinfo);
		fwritedeviceinfostr(pointermac->serialnumberlen, pointermac->serialnumber, fh_deviceinfo);
		fwritedeviceinfostr(pointermac->devicenamelen, pointermac->devicename, fh_deviceinfo);
		if (pointermac->enrolleelen != 0)
		{
			fprintf(fh_deviceinfo, "\t");
			for (p = 0; p < pointermac->enrolleelen; p++)
				fprintf(fh_deviceinfo, "%02x", pointermac->enrollee[p]);
		}
		fwritedeviceinfostr(pointermac->essidlen, pointermac->essid, fh_deviceinfo);
		fprintf(fh_deviceinfo, "\n");
		deviceinfocount++;
	}
	return;
}
/*===========================================================================*/

/*===========================================================================*/
static void processtacacsppacket(uint32_t restlen, uint8_t *tacacspptr)
{
	static uint32_t authlen;
	static tacacsp_t *tacacsp;
	static tacacsplist_t *tacacsplistnew;

	if (restlen < (uint32_t)TACACSP_SIZE)
		return;
	tacacsp = (tacacsp_t *)tacacspptr;
	if (tacacsp->type == TACACS2_AUTHENTICATION)
	{
		tacacsp2count++;
		return;
	}
	if (tacacsp->type == TACACS3_AUTHENTICATION)
	{
		tacacsp3count++;
		return;
	}
	if (tacacsp->type != TACACS_AUTHENTICATION)
		return;
	authlen = ntohl(tacacsp->len);
	if ((authlen > restlen - TACACSP_SIZE) || (authlen > TACACSPMAX_LEN))
		return;
	if (tacacsplistptr >= tacacsplist + tacacsplistmax)
	{
		tacacsplistnew = (tacacsplist_t *)realloc(tacacsplist, (tacacsplistmax + TACACSPLIST_MAX) * TACACSPLIST_SIZE);
		if (tacacsplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		tacacsplist = tacacsplistnew;
		tacacsplistptr = tacacsplistnew + tacacsplistmax;
		tacacsplistmax += TACACSPLIST_MAX;
	}
	memset(tacacsplistptr, 0, TACACSPLIST_SIZE);
	tacacsplistptr->version = tacacsp->version;
	tacacsplistptr->sequencenr = tacacsp->sequencenr;
	tacacsplistptr->sessionid = ntohl(tacacsp->sessionid);
	tacacsplistptr->len = authlen;
	memcpy(tacacsplistptr->data, tacacsp->data, authlen);
	tacacsplistptr++;
	tacacspcount++;
	return;
}
/*===========================================================================*/
static void processprotochappacket(uint32_t restlen, uint8_t *chapptr)
{
	static chap_t *chap;

	if (restlen < (uint32_t)CHAP_SIZE)
		return;
	chap = (chap_t *)chapptr;
	if (chap->code == CHAP_CODE_REQ)
		protochapreqcount++;
	else if (chap->code == CHAP_CODE_RESP)
		protochaprespcount++;
	else if (chap->code == CHAP_CODE_SUCCESS)
		protochapsuccesscount++;
	protochapcount++;
	return;
}
/*===========================================================================*/
static void processprotopapppacket(void)
{

	protopapcount++;
	return;
}
/*===========================================================================*/
static void processptppacket(uint32_t restlen, uint8_t *ptpptr)
{
	static ptp_t *ptp;

	if (restlen < (uint32_t)PTP_SIZE)
		return;
	ptp = (ptp_t *)ptpptr;
	if (ntohs(ptp->type) == PROTO_CHAP)
		processprotochappacket(restlen - PTP_SIZE, ptpptr + PTP_SIZE);
	else if (ntohs(ptp->type) == PROTO_PAP)
		processprotopapppacket();
	return;
}
/*===========================================================================*/
static void processgrepacket(uint32_t restlen, uint8_t *greptr)
{
	static gre_t *gre;
	static uint32_t ofco;

	if (restlen < (uint32_t)GRE_SIZE)
		return;
	gre = (gre_t *)greptr;
	if ((ntohs(gre->flags) & GRE_MASK_VERSION) != 0x1)
		return; /* only GRE v1 supported */
	ofco = 0;
	if ((ntohs(gre->flags) & GRE_FLAG_SNSET) == GRE_FLAG_SNSET)
		ofco += 4;
	if ((ntohs(gre->flags) & GRE_FLAG_ACKSET) == GRE_FLAG_ACKSET)
		ofco += 4;
	if (ntohs(gre->type) == GREPROTO_PPP)
		processptppacket(restlen - GRE_SIZE - ofco, greptr + GRE_SIZE + ofco);
	grecount++;
	return;
}
/*===========================================================================*/
static void processradiuspacket(uint64_t timestamp, uint32_t restlen, uint8_t *radiusptr)
{
	static radius_t *radius;
	static uint16_t radiuslen;

	if (restlen < RADIUS_MIN_SIZE)
		return;
	radius = (radius_t *)radiusptr;
	radiuslen = ntohs(radius->len);
	if (restlen != radiuslen)
		return;
	if (radius->code == RADIUS_ACCESS_REQUEST)
		radiusrequestcount++;
	else if (radius->code == RADIUS_ACCESS_ACCEPT)
		radiusacceptcount++;
	else if (radius->code == RADIUS_ACCESS_REJECT)
		radiusrejectcount++;
	else if (radius->code == RADIUS_ACCESS_CHALLENGE)
		radiuschallengecount++;
	timestamp = timestamp;
	return;
}
/*===========================================================================*/
static void processudppacket(uint64_t timestamp, uint32_t restlen, uint8_t *udpptr)
{
	static udp_t *udp;
	static uint16_t udplen;
	static uint16_t udpsourceport;
	static uint16_t udpdestinationport;

	if (restlen < UDP_SIZE)
		return;
	udp = (udp_t *)udpptr;
	udplen = ntohs(udp->len);
	if (restlen < udplen)
		return;
	udpcount++;
	udpsourceport = ntohs(udp->sourceport);
	udpdestinationport = ntohs(udp->destinationport);
	if ((udpsourceport == UDP_RADIUS_PORT) || (udpdestinationport == UDP_RADIUS_PORT))
		processradiuspacket(timestamp, restlen - UDP_SIZE, udpptr + UDP_SIZE);
	return;
}
/*===========================================================================*/
static void processtcppacket(uint64_t timestamp, uint32_t restlen, uint8_t *tcpptr)
{
	static uint32_t tcplen;
	static tcp_t *tcp;
	static tacacsp_t *tacacsp;

	if (restlen < TCP_SIZE_MIN)
		return;
	tcp = (tcp_t *)tcpptr;
	tcplen = byte_swap_8(tcp->len) * 4;
	if (restlen < tcplen)
		return;
	if (restlen >= (uint32_t)TCP_SIZE_MIN + (uint32_t)TACACSP_SIZE)
	{
		tacacsp = (tacacsp_t *)(tcpptr + tcplen);
		if (tacacsp->version == TACACSP_VERSION)
			processtacacsppacket(restlen - tcplen, tcpptr + tcplen);
	}
	tcpcount++;
	// dummy code to satisfy gcc untill full code is implemented
	timestamp = timestamp;
	return;
}
/*===========================================================================*/
static void processicmp4(void)
{
	icmp4count++;
	return;
}
/*===========================================================================*/
static void processipv4(uint64_t timestamp, uint32_t restlen, uint8_t *ipv4ptr)
{
	static ipv4_t *ipv4;
	static uint32_t ipv4len;

	if (restlen < IPV4_SIZE_MIN)
		return;
	ipv4 = (ipv4_t *)ipv4ptr;
	if ((ipv4->ver_hlen & 0xf0) != 0x40)
		return;
	ipv4len = (ipv4->ver_hlen & 0x0f) * 4;
	if (restlen < ipv4len)
		return;
	if (ipv4->nextprotocol == NEXTHDR_TCP)
		processtcppacket(timestamp, ntohs(ipv4->len) - ipv4len, ipv4ptr + ipv4len);
	else if (ipv4->nextprotocol == NEXTHDR_UDP)
		processudppacket(timestamp, ntohs(ipv4->len) - ipv4len, ipv4ptr + ipv4len);
	else if (ipv4->nextprotocol == NEXTHDR_ICMP4)
		processicmp4();
	else if (ipv4->nextprotocol == NEXTHDR_GRE)
		processgrepacket(ntohs(ipv4->len) - ipv4len, ipv4ptr + ipv4len);
	ipv4count++;
	return;
}
/*===========================================================================*/
static void processicmp6(void)
{
	icmp6count++;
	return;
}
/*===========================================================================*/
static void processipv6(uint64_t timestamp, uint16_t restlen, uint8_t *ipv6ptr)
{
	static ipv6_t *ipv6;

	if (restlen < IPV6_SIZE)
		return;
	ipv6 = (ipv6_t *)ipv6ptr;
	if ((ntohl(ipv6->ver_class) & 0xf0000000) != 0x60000000)
		return;
	if (restlen < ntohs(ipv6->len))
		return;
	if (ipv6->nextprotocol == NEXTHDR_TCP)
		processtcppacket(timestamp, restlen, ipv6ptr + IPV6_SIZE);
	else if (ipv6->nextprotocol == NEXTHDR_UDP)
		processudppacket(timestamp, restlen, ipv6ptr + IPV6_SIZE);
	else if (ipv6->nextprotocol == NEXTHDR_ICMP6)
		processicmp6();
	else if (ipv6->nextprotocol == NEXTHDR_GRE)
		processgrepacket(restlen, ipv6ptr + IPV6_SIZE);
	ipv6count++;
	return;
}
/*===========================================================================*/
static inline bool mschapv2_challenge_hash(uint8_t *peer_challenge, uint8_t *auth_challenge, uint8_t *username, size_t usernamelen, uint8_t *challenge)
{
	static unsigned int shalen;
	static EVP_MD_CTX *mdctx;
	static uint8_t shahash[EVP_MAX_MD_SIZE];

	shalen = 40;
	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL)
		return false;
	if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) == 0)
	{
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	shalen = MSCHAPV2_CHALLENGE_LEN_MAX;
	if (EVP_DigestUpdate(mdctx, peer_challenge, MSCHAPV2_CHALLENGE_PEER_LEN_MAX) == 0)
	{
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	if (EVP_DigestUpdate(mdctx, auth_challenge, MSCHAPV2_CHALLENGE_PEER_LEN_MAX) == 0)
	{
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	if (EVP_DigestUpdate(mdctx, username, usernamelen) == 0)
	{
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	if (EVP_DigestFinal_ex(mdctx, shahash, &shalen) == 0)
	{
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	EVP_MD_CTX_free(mdctx);
	memcpy(challenge, shahash, MSCHAPV2_CHALLENGE_LEN_MAX);
	return true;
}
/*===========================================================================*/
static inline size_t mschapv2_username_clean(uint8_t *username, size_t usernamelen, uint8_t *usernameclean)
{
	static char *ptr;

	ptr = (char *)memchr(username, '\\', usernamelen);
	if (ptr == NULL)
	{
		memcpy(usernameclean, username, usernamelen);
		return usernamelen;
	}
	memcpy(usernameclean, ptr + 1, username + usernamelen - (uint8_t *)ptr - 1);
	return (username + usernamelen - (uint8_t *)ptr - 1);
}
/*===========================================================================*/

/*===========================================================================*/
static void addeapmschapv2hash(uint8_t id, uint8_t mschapv2usernamelen, uint8_t *mschapv2username, uint8_t *mschapv2request, uint8_t *mschapv2response)
{
	static eapmschapv2hashlist_t *eapmschapv2hashlistnew;

	eapmschapv2hashcount++;
	if (eapmschapv2hashlistptr >= eapmschapv2hashlist + eapmschapv2hashlistmax)
	{
		eapmschapv2hashlistnew = (eapmschapv2hashlist_t *)realloc(eapmschapv2hashlist, (eapmschapv2hashlistmax + EAPMSCHAPV2HASHLIST_MAX) * EAPMSCHAPV2HASHLIST_SIZE);
		if (eapmschapv2hashlistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		eapmschapv2hashlist = eapmschapv2hashlistnew;
		eapmschapv2hashlistptr = eapmschapv2hashlistnew + eapmschapv2hashlistmax;
		eapmschapv2hashlistmax += EAPMSCHAPV2HASHLIST_MAX;
	}
	memset(eapmschapv2hashlistptr, 0, EAPMSCHAPV2HASHLIST_SIZE);
	eapmschapv2hashlistptr->id = id;
	memcpy(eapmschapv2hashlistptr->mschapv2request, mschapv2request, MSCHAPV2REQ_LEN_MAX);
	memcpy(eapmschapv2hashlistptr->mschapv2response, mschapv2response, MSCHAPV2RESP_LEN_MAX);
	eapmschapv2hashlistptr->mschapv2usernamelen = mschapv2usernamelen;
	memcpy(eapmschapv2hashlistptr->mschapv2username, mschapv2username, mschapv2usernamelen);
	eapmschapv2hashlistptr++;
	return;
}
/*===========================================================================*/
static void processexteapmschapv2(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t eapcode, uint32_t restlen, uint8_t *eapmschapv2ptr)
{
	static eapmschapv2_t *eapmschapv2;
	static uint16_t eaplen;
	static uint16_t mschapv2len;
	static eapmschapv2msglist_t *pointer;
	static uint32_t mschapv2usernamelen;
	static uint8_t *mschapv2usernameptr;

	eapmschapv2count++;
	eapmschapv2 = (eapmschapv2_t *)eapmschapv2ptr;
	eaplen = ntohs(eapmschapv2->eaplen);
	mschapv2len = ntohs(eapmschapv2->mschapv2len);
	if (eaplen > restlen)
		return;
	if ((eapcode == EAP_CODE_REQ) && (eapmschapv2->opcode == EAP_MSCHAPV2_OPCODE_REQ))
	{
		pointer = eapmschapv2msglist + EAPMSCHAPV2MSGLIST_MAX;
		if (eapmschapv2->mschapv2valuesize != MSCHAPV2REQ_LEN_MAX)
			return;
		memset(pointer, 0, EAPMSCHAPV2MSGLIST_SIZE);
		pointer->timestamp = eaptimestamp;
		memcpy(pointer->ap, macfm, 6);
		memcpy(pointer->client, macto, 6);
		pointer->type = EAP_CODE_REQ;
		pointer->id = eapmschapv2->id;
		memcpy(pointer->mschapv2request, eapmschapv2->mschapv2data, eapmschapv2->mschapv2valuesize);
		mschapv2usernamelen = eaplen - EAPMSCHAPV2_SIZE - eapmschapv2->mschapv2valuesize;
		if (mschapv2usernamelen > MSCHAPV2USERNAME_LEN_MAX)
			return;
		if (EAPMSCHAPV2_SIZE + MSCHAPV2REQ_LEN_MAX + mschapv2usernamelen > restlen)
			return;
		mschapv2usernameptr = eapmschapv2ptr + EAPMSCHAPV2_SIZE + eapmschapv2->mschapv2valuesize;
		if ((fh_identity != 0) && (mschapv2usernamelen > 0))
		{
			fwritestring(mschapv2usernamelen, mschapv2usernameptr, fh_identity);
			identitycount++;
		}
		qsort(eapmschapv2msglist, EAPMSCHAPV2MSGLIST_MAX + 1, EAPMSCHAPV2MSGLIST_SIZE, sort_eapmschapv2msglist_by_timestamp);
	}
	else if ((eapcode == EAP_CODE_RESP) && (eapmschapv2->opcode == EAP_MSCHAPV2_OPCODE_RESP))
	{
		pointer = eapmschapv2msglist + EAPMSCHAPV2MSGLIST_MAX;
		if (mschapv2len != eaplen - EXTEAP_SIZE)
			return;
		if (memcmp(&zeroed32, eapmschapv2->mschapv2data + MSCHAPV2_CHALLENGE_PEER_LEN_MAX + MSCHAPV2_RESERVED_LEN_MAX, MSCHAPV2_NTRESPONSE_LEN_MAX) == 0)
			return;
		if (eapmschapv2->mschapv2valuesize != MSCHAPV2RESP_LEN_MAX)
			return;
		memset(pointer, 0, EAPMSCHAPV2MSGLIST_SIZE);
		pointer->timestamp = eaptimestamp;
		memcpy(pointer->ap, macto, 6);
		memcpy(pointer->client, macfm, 6);
		pointer->type = EAP_CODE_RESP;
		pointer->id = eapmschapv2->id;
		memcpy(pointer->mschapv2response, eapmschapv2->mschapv2data, eapmschapv2->mschapv2valuesize);
		mschapv2usernamelen = restlen - EAPMSCHAPV2_SIZE - eapmschapv2->mschapv2valuesize;
		if (mschapv2usernamelen == 0)
			return;
		if (mschapv2usernamelen > MSCHAPV2USERNAME_LEN_MAX)
			return;
		if (EAPMSCHAPV2_SIZE + MSCHAPV2REQ_LEN_MAX + mschapv2usernamelen > restlen)
			return;
		mschapv2usernameptr = eapmschapv2ptr + EAPMSCHAPV2_SIZE + eapmschapv2->mschapv2valuesize;
		pointer->mschapv2usernamelen = mschapv2usernamelen;
		memcpy(pointer->mschapv2username, mschapv2usernameptr, mschapv2usernamelen);
		if (fh_username != 0)
		{
			fwritestring(mschapv2usernamelen, mschapv2usernameptr, fh_username);
			usernamecount++;
		}
		for (pointer = eapmschapv2msglist; pointer < eapmschapv2msglist + EAPMSCHAPV2MSGLIST_MAX; pointer++)
		{
			if ((pointer->type) != EAP_CODE_REQ)
				continue;
			if ((pointer->id) != eapmschapv2->id)
				continue;
			if (memcmp(pointer->ap, macto, 6) != 0)
				continue;
			if (memcmp(pointer->client, macfm, 6) != 0)
				continue;
			pointer->mschapv2usernamelen = mschapv2usernamelen;
			memcpy(pointer->mschapv2username, mschapv2usernameptr, mschapv2usernamelen);
			addeapmschapv2hash(eapmschapv2->id, pointer->mschapv2usernamelen, pointer->mschapv2username, pointer->mschapv2request, eapmschapv2->mschapv2data);
		}
		qsort(eapmschapv2msglist, EAPMSCHAPV2MSGLIST_MAX + 1, EAPMSCHAPV2MSGLIST_SIZE, sort_eapmschapv2msglist_by_timestamp);
	}
	return;
}
/*===========================================================================*/

/*===========================================================================*/
static void addeapleaphash(uint8_t id, uint8_t leapusernamelen, uint8_t *leapusername, uint8_t *leaprequest, uint8_t *leapresponse)
{
	static eapleaphashlist_t *eapleaphashlistnew;

	eapleaphashcount++;
	if (eapleaphashlistptr >= eapleaphashlist + eapleaphashlistmax)
	{
		eapleaphashlistnew = (eapleaphashlist_t *)realloc(eapleaphashlist, (eapleaphashlistmax + EAPLEAPHASHLIST_MAX) * EAPLEAPHASHLIST_SIZE);
		if (eapleaphashlistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		eapleaphashlist = eapleaphashlistnew;
		eapleaphashlistptr = eapleaphashlistnew + eapleaphashlistmax;
		eapleaphashlistmax += EAPLEAPHASHLIST_MAX;
	}
	memset(eapleaphashlistptr, 0, EAPLEAPHASHLIST_SIZE);
	eapleaphashlistptr->id = id;
	memcpy(eapleaphashlistptr->leaprequest, leaprequest, LEAPREQ_LEN_MAX);
	memcpy(eapleaphashlistptr->leapresponse, leapresponse, LEAPRESP_LEN_MAX);
	eapleaphashlistptr->leapusernamelen = leapusernamelen;
	memcpy(eapleaphashlistptr->leapusername, leapusername, leapusernamelen);
	eapleaphashlistptr++;
	return;
}
/*===========================================================================*/
static void processexteapleap(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t eapcode, uint32_t restlen, uint8_t *eapleapptr)
{
	static eapleap_t *eapleap;
	static uint32_t eapleaplen;
	static eapleapmsglist_t *pointer;
	static uint32_t leapusernamelen;
	static uint8_t *leapusernameptr;

	eapleapcount++;
	eapleap = (eapleap_t *)eapleapptr;
	eapleaplen = ntohs(eapleap->eapleaplen);
	if (eapleaplen > restlen)
		return;
	if (eapleap->version != 1)
		return;
	if (eapleap->reserved != 0)
		return;
	if (eapcode == EAP_CODE_REQ)
	{
		pointer = eapleapmsglist + EAPLEAPMSGLIST_MAX;
		if (eapleap->leaplen != LEAPREQ_LEN_MAX)
			return;
		if (eapleap->leaplen > eapleaplen - EAPLEAP_SIZE)
			return;
		if (eapleap->leaplen == eapleaplen - EAPLEAP_SIZE)
			return;
		if (memcmp(&zeroed32, eapleap->leapdata, LEAPREQ_LEN_MAX) == 0)
			return;
		memset(pointer, 0, EAPLEAPMSGLIST_SIZE);
		pointer->timestamp = eaptimestamp;
		memcpy(pointer->ap, macfm, 6);
		memcpy(pointer->client, macto, 6);
		pointer->type = EAP_CODE_REQ;
		pointer->id = eapleap->id;
		memcpy(pointer->leaprequest, eapleap->leapdata, LEAPREQ_LEN_MAX);
		leapusernamelen = eapleaplen - EAPLEAP_SIZE - LEAPREQ_LEN_MAX;
		if (leapusernamelen == 0)
			return;
		if (leapusernamelen > LEAPUSERNAME_LEN_MAX)
			return;
		if (EAPLEAP_SIZE + LEAPREQ_LEN_MAX + leapusernamelen > restlen)
			return;
		leapusernameptr = eapleapptr + EAPLEAP_SIZE + LEAPREQ_LEN_MAX;
		pointer->leapusernamelen = leapusernamelen;
		memcpy(pointer->leapusername, leapusernameptr, leapusernamelen);
		if (fh_username != 0)
		{
			fwritestring(leapusernamelen, leapusernameptr, fh_username);
			usernamecount++;
		}
		qsort(eapleapmsglist, EAPLEAPMSGLIST_MAX + 1, EAPLEAPMSGLIST_SIZE, sort_eapleapmsglist_by_timestamp);
	}
	else if (eapcode == EAP_CODE_RESP)
	{
		pointer = eapleapmsglist + EAPLEAPMSGLIST_MAX;
		if (eapleap->leaplen != LEAPRESP_LEN_MAX)
			return;
		if (eapleap->leaplen > eapleaplen - EAPLEAP_SIZE)
			return;
		if (memcmp(&zeroed32, eapleap->leapdata, LEAPRESP_LEN_MAX) == 0)
			return;
		memset(pointer, 0, EAPLEAPMSGLIST_SIZE);
		pointer->timestamp = eaptimestamp;
		memcpy(pointer->ap, macto, 6);
		memcpy(pointer->client, macfm, 6);
		pointer->type = EAP_CODE_RESP;
		pointer->id = eapleap->id;
		memcpy(pointer->leapresponse, eapleap->leapdata, LEAPRESP_LEN_MAX);
		for (pointer = eapleapmsglist; pointer < eapleapmsglist + EAPLEAPMSGLIST_MAX; pointer++)
		{
			if ((pointer->type) != EAP_CODE_REQ)
				continue;
			if ((pointer->id) != eapleap->id)
				continue;
			if (memcmp(pointer->ap, macto, 6) != 0)
				continue;
			if (memcmp(pointer->client, macfm, 6) != 0)
				continue;
			addeapleaphash(eapleap->id, pointer->leapusernamelen, pointer->leapusername, pointer->leaprequest, eapleap->leapdata);
		}
		qsort(eapleapmsglist, EAPLEAPMSGLIST_MAX + 1, EAPLEAPMSGLIST_SIZE, sort_eapleapmsglist_by_timestamp);
	}
	return;
}
/*===========================================================================*/

/*===========================================================================*/
static void addeapmd5hash(uint8_t id, uint8_t *challenge, uint8_t *response)
{
	static eapmd5hashlist_t *eapmd5hashlistnew;

	eapmd5hashcount++;
	if (eapmd5hashlistptr >= eapmd5hashlist + eapmd5hashlistmax)
	{
		eapmd5hashlistnew = (eapmd5hashlist_t *)realloc(eapmd5hashlist, (eapmd5hashlistmax + EAPMD5HASHLIST_MAX) * EAPMD5HASHLIST_SIZE);
		if (eapmd5hashlistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		eapmd5hashlist = eapmd5hashlistnew;
		eapmd5hashlistptr = eapmd5hashlistnew + eapmd5hashlistmax;
		eapmd5hashlistmax += EAPMD5HASHLIST_MAX;
	}
	memset(eapmd5hashlistptr, 0, EAPMD5HASHLIST_SIZE);
	eapmd5hashlistptr->id = id;
	memcpy(eapmd5hashlistptr->md5request, challenge, EAPMD5_LEN_MAX);
	memcpy(eapmd5hashlistptr->md5response, response, EAPMD5_LEN_MAX);
	eapmd5hashlistptr++;
	return;
}
/*===========================================================================*/
static void processexteapmd5(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t eapcode, uint32_t restlen, uint8_t *eapmd5ptr)
{
	static eapmd5_t *eapmd5;
	static uint32_t eapmd5len;
	static eapmd5msglist_t *pointer;

	eapmd5count++;
	eapmd5 = (eapmd5_t *)eapmd5ptr;
	eapmd5len = ntohs(eapmd5->eapmd5len);
	if (eapmd5len != restlen)
		return;
	if (eapmd5->md5len != EAPMD5_LEN_MAX)
		return;
	if (memcmp(&zeroed32, eapmd5->md5data, EAPMD5_LEN_MAX) == 0)
		return;
	if (eapcode == EAP_CODE_REQ)
	{
		pointer = eapmd5msglist + EAPMD5MSGLIST_MAX;
		memset(pointer, 0, EAPMD5MSGLIST_SIZE);
		pointer->timestamp = eaptimestamp;
		memcpy(pointer->ap, macfm, 6);
		memcpy(pointer->client, macto, 6);
		pointer->type = EAP_CODE_REQ;
		pointer->id = eapmd5->id;
		memcpy(pointer->md5, eapmd5->md5data, EAPMD5_LEN_MAX);
		qsort(eapmd5msglist, EAPMD5MSGLIST_MAX + 1, EAPMD5MSGLIST_SIZE, sort_eapmd5msglist_by_timestamp);
	}
	else if (eapcode == EAP_CODE_RESP)
	{
		pointer = eapmd5msglist + EAPMD5MSGLIST_MAX;
		memset(pointer, 0, EAPMD5MSGLIST_SIZE);
		pointer->timestamp = eaptimestamp;
		memcpy(pointer->ap, macto, 6);
		memcpy(pointer->client, macfm, 6);
		pointer->type = EAP_CODE_RESP;
		pointer->id = eapmd5->id;
		memcpy(pointer->md5, eapmd5->md5data, EAPMD5_LEN_MAX);
		for (pointer = eapmd5msglist; pointer < eapmd5msglist + EAPMD5MSGLIST_MAX; pointer++)
		{
			if ((pointer->type) != EAP_CODE_REQ)
				continue;
			if ((pointer->id) != eapmd5->id)
				continue;
			if (memcmp(pointer->ap, macto, 6) != 0)
				continue;
			if (memcmp(pointer->client, macfm, 6) != 0)
				continue;
			addeapmd5hash(eapmd5->id, pointer->md5, eapmd5->md5data);
		}
		qsort(eapmd5msglist, EAPMD5MSGLIST_MAX + 1, EAPMD5MSGLIST_SIZE, sort_eapmd5msglist_by_timestamp);
	}
	return;
}
/*===========================================================================*/
/*===========================================================================*/
static bool testfaultypmkid(uint8_t *macsta)
{
	static const uint8_t faulty1[3] =
		{
			0x64, 0x52, 0x99};

	static const uint8_t faulty2[3] =
		{
			0xca, 0x6a, 0x10};

	static const uint8_t faulty3[3] =
		{
			0xcc, 0x6a, 0x10};
	if (memcmp(&faulty1, macsta, 3) == 0)
	{
		pmkidfaultycount++;
		return true;
	}
	if (memcmp(&faulty2, macsta, 3) == 0)
	{
		pmkidfaultycount++;
		return true;
	}
	if (memcmp(&faulty3, macsta, 3) == 0)
	{
		pmkidfaultycount++;
		return true;
	}
	return false;
}
/*===========================================================================*/
static bool testpmkid(uint8_t *testpmk, uint8_t *macsta, uint8_t *macap, uint8_t *pmkid)
{
	static const char *pmkname = "PMK Name";
	static uint8_t pmkidcalc[64];

	memcpy(pmkidcalc, pmkname, 8);
	memcpy(&pmkidcalc[8], macap, 6);
	memcpy(&pmkidcalc[14], macsta, 6);

	if (!EVP_MAC_init(ctxhmac, testpmk, 32, paramssha1))
		return false;
	if (!EVP_MAC_update(ctxhmac, pmkidcalc, 20))
		return false;
	if (!EVP_MAC_final(ctxhmac, pmkidcalc, NULL, 20))
		return false;
	if (memcmp(pmkid, pmkidcalc, 16) != 0)
		return false;
	return true;
}
/*===========================================================================*/
static bool testeapolpmk(uint8_t *testpmk, uint8_t keyver, uint8_t *macsta, uint8_t *macap, uint8_t *nonceap, uint8_t eapollen, uint8_t *eapolmessage)
{
	static uint8_t *pkeptr;
	static wpakey_t *wpakzero, *wpak;
	static uint8_t pkedata[102];
	static uint8_t eapoltmp[1024];

	memset(eapoltmp, 0, sizeof(eapoltmp));
	memcpy(eapoltmp, eapolmessage, eapollen);
	wpakzero = (wpakey_t *)(eapoltmp + EAPAUTH_SIZE);
	wpak = (wpakey_t *)(eapolmessage + EAPAUTH_SIZE);
	memset(wpakzero->keymic, 0, 16);

	if ((keyver == 1) || (keyver == 2))
	{
		memset(&pkedata, 0, sizeof(pkedata));
		pkeptr = pkedata;
		memcpy(pkeptr, "Pairwise key expansion", 23);
		if (memcmp(macap, macsta, 6) < 0)
		{
			memcpy(pkeptr + 23, macap, 6);
			memcpy(pkeptr + 29, macsta, 6);
		}
		else
		{
			memcpy(pkeptr + 23, macsta, 6);
			memcpy(pkeptr + 29, macap, 6);
		}
		if (memcmp(nonceap, wpak->nonce, 32) < 0)
		{
			memcpy(pkeptr + 35, nonceap, 32);
			memcpy(pkeptr + 67, wpak->nonce, 32);
		}
		else
		{
			memcpy(pkeptr + 35, wpak->nonce, 32);
			memcpy(pkeptr + 67, nonceap, 32);
		}
		if (!EVP_MAC_init(ctxhmac, testpmk, 32, paramssha1))
			return false;
		if (!EVP_MAC_update(ctxhmac, pkedata, 100))
			return false;
		if (!EVP_MAC_final(ctxhmac, pkedata, NULL, 100))
			return false;
		if (keyver == 2)
		{
			if (!EVP_MAC_init(ctxhmac, pkedata, 16, paramssha1))
				return false;
			if (!EVP_MAC_update(ctxhmac, eapoltmp, eapollen))
				return false;
			if (!EVP_MAC_final(ctxhmac, eapoltmp, NULL, eapollen))
				return false;
		}
		if (keyver == 1)
		{
			if (!EVP_MAC_init(ctxhmac, pkedata, 16, paramsmd5))
				return false;
			if (!EVP_MAC_update(ctxhmac, eapoltmp, eapollen))
				return false;
			if (!EVP_MAC_final(ctxhmac, eapoltmp, NULL, eapollen))
				return false;
		}
	}
	else if (keyver == 3)
	{
		memset(&pkedata, 0, sizeof(pkedata));
		pkedata[0] = 1;
		pkedata[1] = 0;
		pkeptr = pkedata + 2;
		memcpy(pkeptr, "Pairwise key expansion", 22);
		if (memcmp(macap, macsta, 6) < 0)
		{
			memcpy(pkeptr + 22, macap, 6);
			memcpy(pkeptr + 28, macsta, 6);
		}
		else
		{
			memcpy(pkeptr + 22, macsta, 6);
			memcpy(pkeptr + 28, macap, 6);
		}
		if (memcmp(nonceap, wpak->nonce, 32) < 0)
		{
			memcpy(pkeptr + 34, nonceap, 32);
			memcpy(pkeptr + 66, wpak->nonce, 32);
		}
		else
		{
			memcpy(pkeptr + 34, wpak->nonce, 32);
			memcpy(pkeptr + 66, nonceap, 32);
		}
		pkedata[100] = 0x80;
		pkedata[101] = 1;
		if (!EVP_MAC_init(ctxhmac, testpmk, 32, paramssha256))
			return false;
		if (!EVP_MAC_update(ctxhmac, pkedata, 102))
			return false;
		if (!EVP_MAC_final(ctxhmac, pkedata, NULL, 102))
			return false;
		if (!EVP_MAC_init(ctxcmac, pkedata, 16, paramsaes128))
			return false;
		if (!EVP_MAC_update(ctxcmac, eapoltmp, eapollen))
			return false;
		if (!EVP_MAC_final(ctxcmac, eapoltmp, NULL, eapollen))
			return false;
	}
	if (memcmp(wpak->keymic, eapoltmp, 16) == 0)
		return true;
	return false;
}
/*===========================================================================*/
static bool testzeroedpsk(uint8_t essidlen, uint8_t *essid)
{
	if (PKCS5_PBKDF2_HMAC_SHA1(zeroedpsk, 8, essid, essidlen, 4096, 32, calculatedpmk) == 0)
		return false;
	return true;
}
/*===========================================================================*/
static void getnc(handshakelist_t *pointerhsakt)
{
	static handshakelist_t *pointerhs, *pointerhsold;

	pointerhsold = pointerhsakt;
	for (pointerhs = pointerhsakt; pointerhs < handshakelistptr; pointerhs++)
	{
		if (memcmp(pointerhs->ap, pointerhsold->ap, 6) != 0)
			return;
		pointerhsakt->status |= pointerhs->status & 0xe0;
		pointerhsold->status |= pointerhs->status & 0xe0;
		pointerhsold = pointerhs;
	}
	return;
}
/*===========================================================================*/
static handshakelist_t *gethandshake(maclist2_t *pointermac, handshakelist_t *pointerhsakt)
{
	static int p;
	static handshakelist_t *pointerhs, *pointerhsold;
	static wpakey_t *wpak, *wpaktemp;
	static int i;
	static unsigned char *hcpos;
	static uint8_t keyvertemp;
	static uint8_t eapoltemp[EAPOL_AUTHLEN_MAX];
	static hccapx_t hccapx;
	static hccap_t hccap;
	static time_t tvhs;

	static char timestringhs[32];

	pointerhsold = NULL;
	for (pointerhs = pointerhsakt; pointerhs < handshakelistptr; pointerhs++)
	{
		tvhs = pointerhs->timestamp / 1000000000;
		strftime(timestringhs, 32, "%d.%m.%Y %H:%M:%S", localtime(&tvhs));
		if (donotcleanflag == false)
		{
			if (memcmp(&mac_broadcast, pointerhs->client, 6) == 0)
				continue;
			if (memcmp(&mac_broadcast, pointerhs->ap, 6) == 0)
				continue;
			if (pointerhsold != NULL)
			{
				if ((memcmp(pointerhs->ap, pointerhsold->ap, 6) == 0) && (memcmp(pointerhs->client, pointerhsold->client, 6) == 0))
				{
					if ((pointerhs->status & ST_APLESS) != ST_APLESS)
						getnc(pointerhs);
					continue;
				}
			}
		}

		/*
		7 6 5 4 3 2 1 0
		
		012 - Status Message/EAPOL
		
		4 - ST_APless 

		*/
		if (memcmp(pointermac->addr, pointerhs->ap, 6) == 0)
		{
			eapolmpbestcount++;
			if ((pointerhs->status & ST_APLESS) != ST_APLESS)
				getnc(pointerhs);
			if ((pointerhs->status & ST_APLESS) == ST_APLESS)
				eapolaplesscount++;
			if ((pointerhs->status & 7) == ST_M12E2)
				eapolm12e2count++;
			if ((pointerhs->status & 7) == ST_M14E4)
				eapolm14e4count++;
			if ((pointerhs->status & 7) == ST_M32E2)
				eapolm32e2count++;
			if ((pointerhs->status & 7) == ST_M32E3)
				eapolm32e3count++;
			if ((pointerhs->status & 7) == ST_M34E3)
				eapolm34e3count++;
			if ((pointerhs->status & 7) == ST_M34E4)
				eapolm34e4count++;
			wpak = (wpakey_t *)(pointerhs->eapol + EAPAUTH_SIZE);
			keyvertemp = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
			memcpy(&eapoltemp, pointerhs->eapol, pointerhs->eapauthlen);
			wpaktemp = (wpakey_t *)(eapoltemp + EAPAUTH_SIZE);
			memset(wpaktemp->keymic, 0, 16);
			if (donotcleanflag == false)
			{
				if (testzeroedpsk(pointermac->essidlen, pointermac->essid) == true)
				{
					if (testeapolpmk(calculatedpmk, keyvertemp, pointerhs->client, pointerhs->ap, pointerhs->anonce, pointerhs->eapauthlen, pointerhs->eapol) == true)
					{
						zeroedeapolpskcount++;
						eapolmpbestcount--;
						continue;
					}
				}
			}
			if (fh_pmkideapol != 0)
			{
				// WPA*TYPE*PMKID-ODER-MIC*MACAP*MACSTA*ESSID_HEX*ANONCE*EAPOL*MP
				fprintf(fh_pmkideapol, "WPA*%02d*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
						HCX_TYPE_EAPOL,
						wpak->keymic[0], wpak->keymic[1], wpak->keymic[2], wpak->keymic[3], wpak->keymic[4], wpak->keymic[5], wpak->keymic[6], wpak->keymic[7],
						wpak->keymic[8], wpak->keymic[9], wpak->keymic[10], wpak->keymic[11], wpak->keymic[12], wpak->keymic[13], wpak->keymic[14], wpak->keymic[15],
						pointerhs->ap[0], pointerhs->ap[1], pointerhs->ap[2], pointerhs->ap[3], pointerhs->ap[4], pointerhs->ap[5],
						pointerhs->client[0], pointerhs->client[1], pointerhs->client[2], pointerhs->client[3], pointerhs->client[4], pointerhs->client[5]);
				for (p = 0; p < pointermac->essidlen; p++)
					fprintf(fh_pmkideapol, "%02x", pointermac->essid[p]);
				fprintf(fh_pmkideapol, "*");
				fprintf(fh_pmkideapol, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*",
						pointerhs->anonce[0], pointerhs->anonce[1], pointerhs->anonce[2], pointerhs->anonce[3], pointerhs->anonce[4], pointerhs->anonce[5], pointerhs->anonce[6], pointerhs->anonce[7],
						pointerhs->anonce[8], pointerhs->anonce[9], pointerhs->anonce[10], pointerhs->anonce[11], pointerhs->anonce[12], pointerhs->anonce[13], pointerhs->anonce[14], pointerhs->anonce[15],
						pointerhs->anonce[16], pointerhs->anonce[17], pointerhs->anonce[18], pointerhs->anonce[19], pointerhs->anonce[20], pointerhs->anonce[21], pointerhs->anonce[22], pointerhs->anonce[23],
						pointerhs->anonce[24], pointerhs->anonce[25], pointerhs->anonce[26], pointerhs->anonce[27], pointerhs->anonce[28], pointerhs->anonce[29], pointerhs->anonce[30], pointerhs->anonce[31]);
				for (p = 0; p < pointerhs->eapauthlen; p++)
					fprintf(fh_pmkideapol, "%02x", eapoltemp[p]);
				if (addtimestampflag == false)
					fprintf(fh_pmkideapol, "*%02x\n", pointerhs->status);
				else
					fprintf(fh_pmkideapol, "*%02x\t%s %" PRIu64 "\n", pointerhs->status, timestringhs, pointerhs->timestampgap);
				if (pointerhs->rcgap == 0)
					eapolwrittencount++;
				else
					eapolncwrittencount++;
			}
		}
		if (memcmp(pointerhs->ap, pointermac->addr, 6) > 0)
		{
			pointerhsakt = pointerhs;
			return pointerhsakt;
		}
		pointerhsold = pointerhs;
	}
	return pointerhsakt;
}
/*===========================================================================*/
static pmkidlist_t *getpmkid(maclist2_t *pointermac, pmkidlist_t *pointerpmkidakt)
{
	static int p;
	static pmkidlist_t *pointerpmkid, *pointerpmkidold;
	static time_t tvhs;
	static char timestringhs[32];

	pointerpmkidold = NULL;
	for (pointerpmkid = pointerpmkidakt; pointerpmkid < pmkidlistptr; pointerpmkid++)
	{
		tvhs = pointerpmkid->timestamp / 1000000000;
		strftime(timestringhs, 32, "%d.%m.%Y %H:%M:%S", localtime(&tvhs));
		if (donotcleanflag == false)
		{
			if (memcmp(&mac_broadcast, pointerpmkid->client, 6) == 0)
				continue;
			if (memcmp(&mac_broadcast, pointerpmkid->ap, 6) == 0)
				continue;
			if (pointerpmkidold != NULL)
			{
				if ((memcmp(pointerpmkid->ap, pointerpmkidold->ap, 6) == 0) && (memcmp(pointerpmkid->client, pointerpmkidold->client, 6) == 0))
					continue;
			}
		}
		if (memcmp(pointermac->addr, pointerpmkid->ap, 6) == 0)
		{
			if (donotcleanflag == false)
			{
				if (testzeroedpsk(pointermac->essidlen, pointermac->essid) == true)
				{
					if (testpmkid(calculatedpmk, pointerpmkid->client, pointerpmkid->ap, pointerpmkid->pmkid) == true)
					{
						zeroedpmkidpskcount++;
						continue;
					}
				}
			}
			if (memcmp(&myaktclient, pointerpmkid->client, 6) == 0)
				pmkidroguecount++;
			pmkidbestcount++;
			if (fh_pmkideapol != 0)
			{
				// WPA*TYPE*PMKID-ODER-MIC*MACAP*MACSTA*ESSID_HEX*ANONCE*EAPOL*MP
				fprintf(fh_pmkideapol, "WPA*%02d*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
						HCX_TYPE_PMKID,
						pointerpmkid->pmkid[0], pointerpmkid->pmkid[1], pointerpmkid->pmkid[2], pointerpmkid->pmkid[3], pointerpmkid->pmkid[4], pointerpmkid->pmkid[5], pointerpmkid->pmkid[6], pointerpmkid->pmkid[7],
						pointerpmkid->pmkid[8], pointerpmkid->pmkid[9], pointerpmkid->pmkid[10], pointerpmkid->pmkid[11], pointerpmkid->pmkid[12], pointerpmkid->pmkid[13], pointerpmkid->pmkid[14], pointerpmkid->pmkid[15],
						pointerpmkid->ap[0], pointerpmkid->ap[1], pointerpmkid->ap[2], pointerpmkid->ap[3], pointerpmkid->ap[4], pointerpmkid->ap[5],
						pointerpmkid->client[0], pointerpmkid->client[1], pointerpmkid->client[2], pointerpmkid->client[3], pointerpmkid->client[4], pointerpmkid->client[5]);
				for (p = 0; p < pointermac->essidlen; p++)
					fprintf(fh_pmkideapol, "%02x", pointermac->essid[p]);
				if (addtimestampflag == false)
					fprintf(fh_pmkideapol, "***%02x\n", pointerpmkid->status);
				else
					fprintf(fh_pmkideapol, "***%02x\t%s\n", pointerpmkid->status, timestringhs);
				pmkidwrittenhcount++;
			}
			if ((fh_pmkideapolclient != 0) && ((pointerpmkid->status & PMKID_CLIENT) == PMKID_CLIENT))
			{
				// WPA*TYPE*PMKID-ODER-MIC*MACAP*MACSTA*ESSID_HEX*ANONCE*EAPOL*MP
				fprintf(fh_pmkideapolclient, "WPA*%02d*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
						HCX_TYPE_PMKID,
						pointerpmkid->pmkid[0], pointerpmkid->pmkid[1], pointerpmkid->pmkid[2], pointerpmkid->pmkid[3], pointerpmkid->pmkid[4], pointerpmkid->pmkid[5], pointerpmkid->pmkid[6], pointerpmkid->pmkid[7],
						pointerpmkid->pmkid[8], pointerpmkid->pmkid[9], pointerpmkid->pmkid[10], pointerpmkid->pmkid[11], pointerpmkid->pmkid[12], pointerpmkid->pmkid[13], pointerpmkid->pmkid[14], pointerpmkid->pmkid[15],
						pointerpmkid->ap[0], pointerpmkid->ap[1], pointerpmkid->ap[2], pointerpmkid->ap[3], pointerpmkid->ap[4], pointerpmkid->ap[5],
						pointerpmkid->client[0], pointerpmkid->client[1], pointerpmkid->client[2], pointerpmkid->client[3], pointerpmkid->client[4], pointerpmkid->client[5]);
				for (p = 0; p < pointermac->essidlen; p++)
					fprintf(fh_pmkideapolclient, "%02x", pointermac->essid[p]);
				if (addtimestampflag == false)
					fprintf(fh_pmkideapolclient, "***%02x\n", pointerpmkid->status);
				else
					fprintf(fh_pmkideapolclient, "***%02x\t%s\n", pointerpmkid->status, timestringhs);
				pmkidclientwrittenhcount++;
			}
		}
		if (memcmp(pointerpmkid->ap, pointermac->addr, 6) > 0)
		{
			pointerpmkidakt = pointerpmkid;
			return pointerpmkidakt;
		}
		pointerpmkidold = pointerpmkid;
	}
	return pointerpmkidakt;
}
/*===========================================================================*/
static void outputwpalists(void)
{
	static maclist2_t *pointermac, *pointermacold;
	static handshakelist_t *pointerhsakt;
	static pmkidlist_t *pointerpmkidakt;
	static int essiddupecount;

	qsort(aplist, aplistptr - aplist, MACLIST_SIZE2, sort_maclist_by_mac_count);
	qsort(pmkidlist, pmkidlistptr - pmkidlist, PMKIDLIST_SIZE, sort_pmkidlist_by_mac);
	if (ncvalue == 0)
		qsort(handshakelist, handshakelistptr - handshakelist, HANDSHAKELIST_SIZE, sort_handshakelist_by_timegap);
	else
		qsort(handshakelist, handshakelistptr - handshakelist, HANDSHAKELIST_SIZE, sort_handshakelist_by_rcgap);
	pointerhsakt = handshakelist;
	pointerpmkidakt = pmkidlist;
	pointermacold = aplist;

	if ((pointermacold->type & AP) == AP)
	{
		if (pointermacold->essidlen != 0)
		{
			if (ignoreieflag == true)
			{
				pointerpmkidakt = getpmkid(pointermacold, pointerpmkidakt);
				pointerhsakt = gethandshake(pointermacold, pointerhsakt);
			}
			else
			{
				if (((pointermacold->akm & TAK_PSK) == TAK_PSK) || ((pointermacold->akm & TAK_PSKSHA256) == TAK_PSKSHA256))
				{
					pointerpmkidakt = getpmkid(pointermacold, pointerpmkidakt);
					pointerhsakt = gethandshake(pointermacold, pointerhsakt);
				}
			}
		}
	}
	essiddupecount = 0;
	for (pointermac = aplist + 1; pointermac < aplistptr; pointermac++)
	{
		if (pointermac->essidlen == 0)
			continue;
		if ((pointermac->type & AP) != AP)
		{
			essiddupecount = 0;
			continue;
		}
		if ((pointermacold->type & AP) == AP)
		{
			if (memcmp(pointermacold->addr, pointermac->addr, 6) == 0)
			{
				essiddupecount++;
				if (essiddupecount >= essiddupemax)
					essiddupemax = essiddupecount;
				if (essiddupecount >= essidsvalue)
					continue;
			}
			else
				essiddupecount = 0;
		}
		if (ignoreieflag == true)
		{
			pointerpmkidakt = getpmkid(pointermac, pointerpmkidakt);
			pointerhsakt = gethandshake(pointermac, pointerhsakt);
		}
		else
		{
			if (((pointermac->akm & TAK_PSK) == TAK_PSK) || ((pointermac->akm & TAK_PSKSHA256) == TAK_PSKSHA256))
			{
				pointerpmkidakt = getpmkid(pointermac, pointerpmkidakt);
				pointerhsakt = gethandshake(pointermac, pointerhsakt);
			}
		}
		pointermacold = pointermac;
	}
	return;
}
/*===========================================================================*/
static void cleanupmac(void)
{
	static maclist2_t *pointer;
	static maclist2_t *pointerold;

	if (aplistptr == aplist)
		return;
	qsort(aplist, aplistptr - aplist, MACLIST_SIZE2, sort_maclist_by_mac);
	pointerold = aplist;
	for (pointer = aplist + 1; pointer < aplistptr; pointer++)
	{
		if (memcmp(pointerold->addr, pointer->addr, 6) == 0)
		{
			if (pointerold->essidlen == pointer->essidlen)
			{
				if (memcmp(pointerold->essid, pointer->essid, pointerold->essidlen) == 0)
				{
					pointerold->timestamp = pointer->timestamp;
					pointerold->type |= pointer->type;
					pointerold->status |= pointer->status;
					pointerold->count += 1;
					pointerold->groupcipher |= pointer->groupcipher;
					pointerold->cipher |= pointer->cipher;
					pointerold->akm |= pointer->akm;
					if (pointerold->manufacturerlen == 0)
					{
						memcpy(pointerold->manufacturer, pointer->manufacturer, pointer->manufacturerlen);
						pointerold->manufacturerlen = pointer->manufacturerlen;
					}
					if (pointerold->modellen == 0)
					{
						memcpy(pointerold->model, pointer->model, pointer->modellen);
						pointerold->modellen = pointer->modellen;
					}
					if (pointerold->serialnumberlen == 0)
					{
						memcpy(pointerold->serialnumber, pointer->serialnumber, pointer->serialnumberlen);
						pointerold->serialnumberlen = pointer->serialnumberlen;
					}
					if (pointerold->devicenamelen == 0)
					{
						memcpy(pointerold->devicename, pointer->devicename, pointer->devicenamelen);
						pointerold->devicenamelen = pointer->devicenamelen;
					}
					if (pointerold->enrolleelen == 0)
					{
						memcpy(pointerold->enrollee, pointer->enrollee, pointer->enrolleelen);
						pointerold->enrolleelen = pointer->enrolleelen;
					}
					pointer->type = REMOVED;
					continue;
				}
			}
		}
		pointerold = pointer;
	}
	return;
}
/*===========================================================================*/
static bool cleanbackhandshake(void)
{
	static int c;
	static handshakelist_t *pointer;

	if (donotcleanflag == true)
		return false;
	pointer = handshakelistptr;
	for (c = 0; c < 20; c++)
	{
		pointer--;
		if (pointer < handshakelist)
			return false;
		if (memcmp(pointer->ap, handshakelistptr->ap, 6) != 0)
			continue;
		if (memcmp(pointer->client, handshakelistptr->client, 6) != 0)
			continue;
		if (memcmp(pointer->anonce, handshakelistptr->anonce, 32) != 0)
			continue;
		if (pointer->eapauthlen != handshakelistptr->eapauthlen)
			continue;
		if (memcmp(pointer->eapol, handshakelistptr->eapol, handshakelistptr->eapauthlen) != 0)
			continue;
		if (pointer->timestampgap > handshakelistptr->timestampgap)
			pointer->timestampgap = handshakelistptr->timestampgap;
		if (pointer->rcgap > handshakelistptr->rcgap)
			pointer->rcgap = (pointer->rcgap & 0xe0) | handshakelistptr->rcgap;
		if (pointer->status < handshakelistptr->status)
			pointer->status = handshakelistptr->status;
		pointer->messageap |= handshakelistptr->messageap;
		pointer->messageclient |= handshakelistptr->messageclient;
		pointer->timestamp |= handshakelistptr->timestamp;
		return true;
	}
	return false;
}
/*===========================================================================*/
static void addhandshake(uint64_t eaptimegap, uint64_t rcgap, messagelist_t *msgclient, messagelist_t *msgap, uint8_t keyver, uint8_t mpfield)
{
	static handshakelist_t *handshakelistnew;
	static messagelist_t *pointer;

	eapolmpcount++;
	if ((mpfield & ST_APLESS) != ST_APLESS)
	{
		for (pointer = messagelist; pointer < messagelist + MESSAGELIST_MAX; pointer++)
		{
			if ((pointer->status & ST_APLESS) != ST_APLESS)
			{
				if (memcmp(msgap->ap, pointer->ap, 6) == 0)
					mpfield |= pointer->status & 0xe0;
			}
		}
	}
	if (msgap->timestamp == msgclient->timestamp)
		eapolmsgtimestamperrorcount++;
	if (testeapolpmk(zeroedpmk, keyver, msgclient->client, msgap->ap, msgap->nonce, msgclient->eapauthlen, msgclient->eapol) == false)
	{
		if (handshakelistptr >= handshakelist + handshakelistmax)
		{
			handshakelistnew = (handshakelist_t *)realloc(handshakelist, (handshakelistmax + HANDSHAKELIST_MAX) * HANDSHAKELIST_SIZE);
			if (handshakelistnew == NULL)
			{
				printError("failed to allocate memory for internal list", 1);
				exit(EXIT_FAILURE);
			}
			handshakelist = handshakelistnew;
			handshakelistptr = handshakelistnew + handshakelistmax;
			handshakelistmax += HANDSHAKELIST_MAX;
		}
		memset(handshakelistptr, 0, HANDSHAKELIST_SIZE);
		handshakelistptr->timestampgap = eaptimegap;
		handshakelistptr->status = mpfield;
		handshakelistptr->rcgap = rcgap;
		if (handshakelistptr->rcgap > 0)
			handshakelistptr->status |= ST_NC;
		handshakelistptr->messageap = msgap->message;
		handshakelistptr->messageclient = msgclient->message;
		memcpy(handshakelistptr->ap, msgap->ap, 6);
		memcpy(handshakelistptr->client, msgclient->client, 6);
		memcpy(handshakelistptr->anonce, msgap->nonce, 32);
		memcpy(handshakelistptr->pmkid, msgap->pmkid, 32);
		handshakelistptr->eapauthlen = msgclient->eapauthlen;
		memcpy(handshakelistptr->eapol, msgclient->eapol, msgclient->eapauthlen);
		handshakelistptr->timestamp = msgclient->timestamp;
		if (cleanbackhandshake() == false)
			handshakelistptr++;
	}
	else
	{
		zeroedeapolpmkcount++;
		if (donotcleanflag == true)
		{
			if (handshakelistptr >= handshakelist + handshakelistmax)
			{
				handshakelistnew = (handshakelist_t *)realloc(handshakelist, (handshakelistmax + HANDSHAKELIST_MAX) * HANDSHAKELIST_SIZE);
				if (handshakelistnew == NULL)
				{
					printError("failed to allocate memory for internal list", 1);
					exit(EXIT_FAILURE);
				}
				handshakelist = handshakelistnew;
				handshakelistptr = handshakelistnew + handshakelistmax;
				handshakelistmax += HANDSHAKELIST_MAX;
			}
			memset(handshakelistptr, 0, HANDSHAKELIST_SIZE);
			handshakelistptr->timestampgap = eaptimegap;
			handshakelistptr->status = mpfield;
			handshakelistptr->rcgap = rcgap;
			if (handshakelistptr->rcgap > 0)
				handshakelistptr->status |= ST_NC;
			handshakelistptr->messageap = msgap->message;
			handshakelistptr->messageclient = msgclient->message;
			memcpy(handshakelistptr->ap, msgap->ap, 6);
			memcpy(handshakelistptr->client, msgclient->client, 6);
			memcpy(handshakelistptr->anonce, msgap->nonce, 32);
			memcpy(handshakelistptr->pmkid, msgap->pmkid, 32);
			handshakelistptr->eapauthlen = msgclient->eapauthlen;
			memcpy(handshakelistptr->eapol, msgclient->eapol, msgclient->eapauthlen);
			handshakelistptr->timestamp = msgclient->timestamp;
			if (cleanbackhandshake() == false)
				handshakelistptr++;
		}
	}
	return;
}
/*===========================================================================*/
static bool cleanbackpmkid(void)
{
	static int c;
	static pmkidlist_t *pointer;

	if (donotcleanflag == true)
		return false;
	pointer = pmkidlistptr;
	for (c = 0; c < 20; c++)
	{
		pointer--;
		if (pointer < pmkidlist)
			return false;
		if (memcmp(pointer->ap, pmkidlistptr->ap, 6) != 0)
			continue;
		if (memcmp(pointer->client, pmkidlistptr->client, 6) != 0)
			continue;
		if (memcmp(pointer->pmkid, pmkidlistptr->pmkid, 16) != 0)
			continue;
		pointer->status |= pmkidlistptr->status;
		return true;
	}
	return false;
}
/*===========================================================================*/
static void addpmkid(uint64_t timestamp, uint8_t *macclient, uint8_t *macap, uint8_t *pmkid, uint8_t pmkidstatus)
{
	static pmkidlist_t *pmkidlistnew;

	pmkidcount++;
	if ((pmkidstatus & PMKID_CLIENT) == PMKID_CLIENT)
	{
		if (testfaultypmkid(macclient) == true)
			return;
	}
	if (testpmkid(zeroedpmk, macclient, macap, pmkid) == false)
	{
		if (pmkidlistptr >= pmkidlist + pmkidlistmax)
		{
			pmkidlistnew = (pmkidlist_t *)realloc(pmkidlist, (pmkidlistmax + PMKIDLIST_MAX) * PMKIDLIST_SIZE);
			if (pmkidlistnew == NULL)
			{
				printError("failed to allocate memory for internal list", 1);
				exit(EXIT_FAILURE);
			}
			pmkidlist = pmkidlistnew;
			pmkidlistptr = pmkidlistnew + pmkidlistmax;
			pmkidlistmax += PMKIDLIST_MAX;
		}
		memset(pmkidlistptr, 0, PMKIDLIST_SIZE);
		memcpy(pmkidlistptr->ap, macap, 6);
		memcpy(pmkidlistptr->client, macclient, 6);
		memcpy(pmkidlistptr->pmkid, pmkid, 16);
		pmkidlistptr->timestamp = timestamp;
		pmkidlistptr->status |= pmkidstatus;
		if (cleanbackpmkid() == false)
			pmkidlistptr++;
	}
	else
	{
		zeroedpmkidpmkcount++;
		if (donotcleanflag == true)
		{
			if (pmkidlistptr >= pmkidlist + pmkidlistmax)
			{
				pmkidlistnew = (pmkidlist_t *)realloc(pmkidlist, (pmkidlistmax + PMKIDLIST_MAX) * PMKIDLIST_SIZE);
				if (pmkidlistnew == NULL)
				{
					printError("failed to allocate memory for internal list", 1);
					exit(EXIT_FAILURE);
				}
				pmkidlist = pmkidlistnew;
				pmkidlistptr = pmkidlistnew + maclistmax;
				pmkidlistmax += PMKIDLIST_MAX;
			}
			memset(pmkidlistptr, 0, PMKIDLIST_SIZE);
			memcpy(pmkidlistptr->ap, macap, 6);
			memcpy(pmkidlistptr->client, macclient, 6);
			memcpy(pmkidlistptr->pmkid, pmkid, 16);
			pmkidlistptr->status |= pmkidstatus;
			if (cleanbackpmkid() == false)
				pmkidlistptr++;
		}
	}
	return;
}
/*===========================================================================*/
static void process80211exteap(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint32_t restlen, uint8_t *eapptr)
{
	static eapauth_t *eapauth;
	static uint32_t authlen;
	static exteap_t *exteap;
	static uint32_t exteaplen;
	static uint32_t idstrlen;

	eapcount++;
	if (restlen < (int)EAPAUTH_SIZE)
		return;
	eapauth = (eapauth_t *)eapptr;
	authlen = ntohs(eapauth->len);
	if (authlen > restlen)
		return;
	exteap = (exteap_t *)(eapptr + EAPAUTH_SIZE);
	exteaplen = ntohs(exteap->len);
	if (exteaplen > authlen)
		return;
	idstrlen = exteaplen - EXTEAP_SIZE;
	if (exteap->type == EAP_TYPE_SIM)
		eapsimcount++;
	else if (exteap->type == EAP_TYPE_AKA)
		eapakacount++;
	else if (exteap->type == EAP_TYPE_PEAP)
		eappeapcount++;
	else if (exteap->type == EAP_TYPE_TLS)
		eaptlscount++;
	else if (exteap->type == EAP_TYPE_EXPAND)
		eapexpandedcount++;
	else if (exteap->type == EAP_TYPE_MD5)
		processexteapmd5(eaptimestamp, macto, macfm, exteap->code, exteaplen, eapptr + EAPAUTH_SIZE);
	else if (exteap->type == EAP_TYPE_LEAP)
		processexteapleap(eaptimestamp, macto, macfm, exteap->code, exteaplen, eapptr + EAPAUTH_SIZE);
	else if (exteap->type == EAP_TYPE_MSEAP)
		processexteapmschapv2(eaptimestamp, macto, macfm, exteap->code, exteaplen, eapptr + EAPAUTH_SIZE);

	if (exteap->code == EAP_CODE_REQ)
	{
		eapcodereqcount++;
		if (exteap->type == EAP_TYPE_ID)
		{
			if (idstrlen > 1)
			{
				if (eapptr[EAPAUTH_SIZE + EXTEAP_SIZE] != 0)
				{
					identitycount++;
					if (fh_identity != NULL)
						fwritestring(idstrlen, &eapptr[EAPAUTH_SIZE + EXTEAP_SIZE], fh_identity);
				}
				else if (eapptr[EAPAUTH_SIZE + EXTEAP_SIZE + 1] != 0)
				{
					identitycount++;
					if (fh_identity != NULL)
						fwritestring(idstrlen - 1, &eapptr[EAPAUTH_SIZE + EXTEAP_SIZE + 1], fh_identity);
				}
			}
			eapidcount++;
		}
	}
	else if (exteap->code == EAP_CODE_RESP)
	{
		eapcoderespcount++;
		if (exteap->type == EAP_TYPE_ID)
		{
			if (idstrlen > 1)
			{
				if (eapptr[EAPAUTH_SIZE + EXTEAP_SIZE] != 0)
				{
					identitycount++;
					if (fh_identity != NULL)
						fwritestring(idstrlen, &eapptr[EAPAUTH_SIZE + EXTEAP_SIZE], fh_identity);
				}
				else if (eapptr[EAPAUTH_SIZE + EXTEAP_SIZE + 1] != 0)
				{
					identitycount++;
					if (fh_identity != NULL)
						fwritestring(idstrlen - 1, &eapptr[EAPAUTH_SIZE + EXTEAP_SIZE + 1], fh_identity);
				}
			}
			eapidcount++;
		}
	}
	return;
}
/*===========================================================================*/
static bool gettagwps(int wpslen, uint8_t *tagptr, tags_t *pointer)
{
	static wpsie_t *wpsptr;

	wpslen -= WPSVENDOR_SIZE;
	tagptr += WPSVENDOR_SIZE;
	if (wpslen < (int)WPSIE_SIZE)
		return true;
	pointer->wpsinfo = 1;
	wpsptr = (wpsie_t *)tagptr;
	if (ntohs(wpsptr->type) != WPS_VERSION)
		return true;
	if (ntohs(wpsptr->len) != 1)
		return true;
	if (wpsptr->data[0] != 0x10)
		return true;
	tagptr += ntohs(wpsptr->len) + WPSIE_SIZE;
	wpslen -= ntohs(wpsptr->len) + WPSIE_SIZE;
	while (0 < wpslen)
	{
		wpsptr = (wpsie_t *)tagptr;
		if ((ntohs(wpsptr->type) == WPS_MANUFACTURER) && (ntohs(wpsptr->len) > 0) && (ntohs(wpsptr->len) < DEVICE_INFO_MAX))
		{
			pointer->manufacturerlen = ntohs(wpsptr->len);
			memcpy(pointer->manufacturer, wpsptr->data, pointer->manufacturerlen);
		}
		else if ((ntohs(wpsptr->type) == WPS_MODELNAME) && (ntohs(wpsptr->len) > 0) && (ntohs(wpsptr->len) < DEVICE_INFO_MAX))
		{
			pointer->modellen = ntohs(wpsptr->len);
			memcpy(pointer->model, wpsptr->data, pointer->modellen);
		}
		else if ((ntohs(wpsptr->type) == WPS_SERIALNUMBER) && (ntohs(wpsptr->len) > 0) && (ntohs(wpsptr->len) < DEVICE_INFO_MAX))
		{
			pointer->serialnumberlen = ntohs(wpsptr->len);
			memcpy(pointer->serialnumber, wpsptr->data, pointer->serialnumberlen);
		}
		else if ((ntohs(wpsptr->type) == WPS_DEVICENAME) && (ntohs(wpsptr->len) > 0) && (ntohs(wpsptr->len) < DEVICE_INFO_MAX))
		{
			pointer->devicenamelen = ntohs(wpsptr->len);
			memcpy(pointer->devicename, wpsptr->data, pointer->devicenamelen);
		}
		else if ((ntohs(wpsptr->type) == WPS_UUIDE) && (ntohs(wpsptr->len) == WPS_ENROLLEE_LEN))
		{
			pointer->enrolleelen = ntohs(wpsptr->len);
			memcpy(pointer->enrollee, wpsptr->data, pointer->enrolleelen);
		}
		tagptr += ntohs(wpsptr->len) + WPSIE_SIZE;
		wpslen -= ntohs(wpsptr->len) + WPSIE_SIZE;
	}
	if (wpslen != 0)
		return false;
	return true;
}
/*===========================================================================*/
static bool gettagwpa(int wpalen, uint8_t *ieptr, tags_t *pointer)
{
	static int c;
	static wpaie_t *wpaptr;
	static int wpatype;
	static suite_t *gsuiteptr;
	static suitecount_t *csuitecountptr;
	static suite_t *csuiteptr;
	static int csuitecount;
	static suitecount_t *asuitecountptr;
	static suite_t *asuiteptr;
	static int asuitecount;

	wpaptr = (wpaie_t *)ieptr;
	wpalen -= WPAIE_SIZE;
	ieptr += WPAIE_SIZE;
#ifndef BIG_ENDIAN_HOST
	wpatype = wpaptr->type;
#else
	wpatype = byte_swap_16(wpaptr->type);
#endif
	if (wpatype != VT_WPA_IE)
		return false;
	pointer->kdversion |= KV_WPAIE;
	gsuiteptr = (suite_t *)ieptr;
	if (memcmp(gsuiteptr->oui, &ouimscorp, 3) == 0)
	{
		if (gsuiteptr->type == CS_WEP40)
			pointer->groupcipher |= TCS_WEP40;
		if (gsuiteptr->type == CS_TKIP)
			pointer->groupcipher |= TCS_TKIP;
		if (gsuiteptr->type == CS_WRAP)
			pointer->groupcipher |= TCS_WRAP;
		if (gsuiteptr->type == CS_CCMP)
			pointer->groupcipher |= TCS_CCMP;
		if (gsuiteptr->type == CS_WEP104)
			pointer->groupcipher |= TCS_WEP104;
		if (gsuiteptr->type == CS_BIP)
			pointer->groupcipher |= TCS_BIP;
		if (gsuiteptr->type == CS_NOT_ALLOWED)
			pointer->groupcipher = TCS_NOT_ALLOWED;
	}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	csuitecountptr = (suitecount_t *)ieptr;
	wpalen -= SUITECOUNT_SIZE;
	ieptr += SUITECOUNT_SIZE;
#ifndef BIG_ENDIAN_HOST
	csuitecount = csuitecountptr->count;
#else
	csuitecount = byte_swap_16(csuitecountptr->count);
#endif
	if (csuitecount * 4 > wpalen)
	{
		taglenerrorcount++;
		return false;
	}
	for (c = 0; c < csuitecount; c++)
	{
		csuiteptr = (suite_t *)ieptr;
		if (memcmp(csuiteptr->oui, &ouimscorp, 3) == 0)
		{
			if (csuiteptr->type == CS_WEP40)
				pointer->cipher |= TCS_WEP40;
			if (csuiteptr->type == CS_TKIP)
				pointer->cipher |= TCS_TKIP;
			if (csuiteptr->type == CS_WRAP)
				pointer->cipher |= TCS_WRAP;
			if (csuiteptr->type == CS_CCMP)
				pointer->cipher |= TCS_CCMP;
			if (csuiteptr->type == CS_WEP104)
				pointer->cipher |= TCS_WEP104;
			if (csuiteptr->type == CS_BIP)
				pointer->cipher |= TCS_BIP;
			if (csuiteptr->type == CS_NOT_ALLOWED)
				pointer->cipher |= TCS_NOT_ALLOWED;
		}
		wpalen -= SUITE_SIZE;
		ieptr += SUITE_SIZE;
		if (wpalen == 0)
			return true;
		if (wpalen < 0)
			return false;
	}
	asuitecountptr = (suitecount_t *)ieptr;
	wpalen -= SUITECOUNT_SIZE;
	ieptr += SUITECOUNT_SIZE;
#ifndef BIG_ENDIAN_HOST
	asuitecount = asuitecountptr->count;
#else
	asuitecount = byte_swap_16(asuitecountptr->count);
#endif
	if (asuitecount * 4 > wpalen)
	{
		taglenerrorcount++;
		return false;
	}
	for (c = 0; c < asuitecount; c++)
	{
		asuiteptr = (suite_t *)ieptr;
		if (memcmp(asuiteptr->oui, &ouimscorp, 3) == 0)
		{
			if (asuiteptr->type == AK_PMKSA)
				pointer->akm |= TAK_PMKSA;
			if (asuiteptr->type == AK_PSK)
				pointer->akm |= TAK_PSK;
			if (asuiteptr->type == AK_FT)
				pointer->akm |= TAK_FT;
			if (asuiteptr->type == AK_FT_PSK)
				pointer->akm |= TAK_FT_PSK;
			if (asuiteptr->type == AK_PMKSA256)
				pointer->akm |= TAK_PMKSA256;
			if (asuiteptr->type == AK_PSKSHA256)
				pointer->akm |= TAK_PSKSHA256;
			if (asuiteptr->type == AK_TDLS)
				pointer->akm |= TAK_TDLS;
			if (asuiteptr->type == AK_SAE_SHA256)
				pointer->akm |= TAK_SAE_SHA256;
			if (asuiteptr->type == AK_FT_SAE)
				pointer->akm |= TAK_FT_SAE;
			if (asuiteptr->type == AK_SAE_SHA384B)
				pointer->akm |= TAK_SAE_SHA384B;
			if (asuiteptr->type == AK_OWE)
				pointer->akm |= TAK_OWE;
		}
		wpalen -= SUITE_SIZE;
		ieptr += SUITE_SIZE;
		if (wpalen == 0)
			return true;
		if (wpalen < 0)
			return false;
	}
	return true;
}
/*===========================================================================*/
static bool gettagvendor(int vendorlen, uint8_t *ieptr, tags_t *pointer)
{
	static wpaie_t *wpaptr;

	static const uint8_t hcxoui[] =
		{
			0xff, 0xff, 0xff, 0x00, 0xd9, 0x20, 0x21, 0x9b, 0x9b, 0x6a, 0xc9, 0x59, 0x49, 0x42, 0xe6, 0x55,
			0x6a, 0x06, 0xa3, 0x23, 0x94, 0x2d, 0x94};

	wpaptr = (wpaie_t *)ieptr;
	if (memcmp(wpaptr->oui, &ouimscorp, 3) == 0)
	{
		if ((wpaptr->ouitype == VT_WPA_IE) && (vendorlen >= WPAIE_LEN_MIN))
		{
			if (gettagwpa(vendorlen, ieptr, pointer) == false)
				return false;
			return true;
		}
		if ((wpaptr->ouitype == VT_WPS_IE) && (vendorlen >= (int)WPSIE_SIZE))
		{
			if (gettagwps(vendorlen, ieptr, pointer) == false)
				return false;
			return true;
		}
		return true;
	}
	if (vendorlen == 0x17)
	{
		if (memcmp(&hcxoui, ieptr, 0x17) == 0)
			beaconhcxcount++;
	}
	return true;
}
/*===========================================================================*/
static bool gettagrsn(int rsnlen, uint8_t *ieptr, tags_t *pointer)
{
	static int c;
	static rsnie_t *rsnptr;
	static int rsnver;
	static suite_t *gsuiteptr;
	static suitecount_t *csuitecountptr;
	static suite_t *csuiteptr;
	static int csuitecount;
	static suitecount_t *asuitecountptr;
	static suite_t *asuiteptr;
	static int asuitecount;
	static rsnpmkidlist_t *rsnpmkidlistptr;
	static int rsnpmkidcount;

	static const uint8_t foxtrott[4] = {0xff, 0xff, 0xff, 0xff};

	rsnptr = (rsnie_t *)ieptr;
#ifndef BIG_ENDIAN_HOST
	rsnver = rsnptr->version;
#else
	rsnver = byte_swap_16(rsnptr->version);
#endif
	if (rsnver != 1)
		return true;
	pointer->kdversion |= KV_RSNIE;
	rsnlen -= RSNIE_SIZE;
	ieptr += RSNIE_SIZE;
	gsuiteptr = (suite_t *)ieptr;
	if (memcmp(gsuiteptr->oui, &suiteoui, 3) == 0)
	{
		if (gsuiteptr->type == CS_WEP40)
			pointer->groupcipher |= TCS_WEP40;
		if (gsuiteptr->type == CS_TKIP)
			pointer->groupcipher |= TCS_TKIP;
		if (gsuiteptr->type == CS_WRAP)
			pointer->groupcipher |= TCS_WRAP;
		if (gsuiteptr->type == CS_CCMP)
			pointer->groupcipher |= TCS_CCMP;
		if (gsuiteptr->type == CS_GCMP)
			pointer->groupcipher |= TCS_GCMP;
		if (gsuiteptr->type == CS_WEP104)
			pointer->groupcipher |= TCS_WEP104;
		if (gsuiteptr->type == CS_BIP)
			pointer->groupcipher |= TCS_BIP;
		if (gsuiteptr->type == CS_NOT_ALLOWED)
			pointer->groupcipher |= TCS_NOT_ALLOWED;
	}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	csuitecountptr = (suitecount_t *)ieptr;
	rsnlen -= SUITECOUNT_SIZE;
	ieptr += SUITECOUNT_SIZE;
#ifndef BIG_ENDIAN_HOST
	csuitecount = csuitecountptr->count;
#else
	csuitecount = byte_swap_16(csuitecountptr->count);
#endif
	if (csuitecount * 4 > rsnlen)
	{
		taglenerrorcount++;
		return false;
	}
	for (c = 0; c < csuitecount; c++)
	{
		csuiteptr = (suite_t *)ieptr;
		if (memcmp(csuiteptr->oui, &suiteoui, 3) == 0)
		{
			if (csuiteptr->type == CS_WEP40)
				pointer->cipher |= TCS_WEP40;
			if (csuiteptr->type == CS_TKIP)
				pointer->cipher |= TCS_TKIP;
			if (csuiteptr->type == CS_WRAP)
				pointer->cipher |= TCS_WRAP;
			if (csuiteptr->type == CS_CCMP)
				pointer->cipher |= TCS_CCMP;
			if (csuiteptr->type == CS_GCMP)
				pointer->cipher |= TCS_GCMP;
			if (csuiteptr->type == CS_WEP104)
				pointer->cipher |= TCS_WEP104;
			if (csuiteptr->type == CS_BIP)
				pointer->cipher |= TCS_BIP;
			if (csuiteptr->type == CS_NOT_ALLOWED)
				pointer->cipher |= TCS_NOT_ALLOWED;
		}
		rsnlen -= SUITE_SIZE;
		ieptr += SUITE_SIZE;
		if (rsnlen < 0)
			return false;
		if (rsnlen == 0)
			return true;
	}
	asuitecountptr = (suitecount_t *)ieptr;
	rsnlen -= SUITECOUNT_SIZE;
	ieptr += SUITECOUNT_SIZE;
#ifndef BIG_ENDIAN_HOST
	asuitecount = asuitecountptr->count;
#else
	asuitecount = byte_swap_16(asuitecountptr->count);
#endif
	if (asuitecount * 4 > rsnlen)
	{
		taglenerrorcount++;
		return false;
	}
	for (c = 0; c < asuitecount; c++)
	{
		asuiteptr = (suite_t *)ieptr;
		if (memcmp(asuiteptr->oui, &suiteoui, 3) == 0)
		{
			if (asuiteptr->type == AK_PMKSA)
				pointer->akm |= TAK_PMKSA;
			if (asuiteptr->type == AK_PSK)
				pointer->akm |= TAK_PSK;
			if (asuiteptr->type == AK_FT)
				pointer->akm |= TAK_FT;
			if (asuiteptr->type == AK_FT_PSK)
				pointer->akm |= TAK_FT_PSK;
			if (asuiteptr->type == AK_PMKSA256)
				pointer->akm |= TAK_PMKSA256;
			if (asuiteptr->type == AK_PSKSHA256)
				pointer->akm |= TAK_PSKSHA256;
			if (asuiteptr->type == AK_TDLS)
				pointer->akm |= TAK_TDLS;
			if (asuiteptr->type == AK_SAE_SHA256)
				pointer->akm |= TAK_SAE_SHA256;
			if (asuiteptr->type == AK_FT_SAE)
				pointer->akm |= TAK_FT_SAE;
			if (asuiteptr->type == AK_SAE_SHA384B)
				pointer->akm |= TAK_SAE_SHA384B;
			if (asuiteptr->type == AK_OWE)
				pointer->akm |= TAK_OWE;
		}
		rsnlen -= SUITE_SIZE;
		ieptr += SUITE_SIZE;
		if (rsnlen < 0)
			return false;
		if (rsnlen == 0)
			return true;
	}
	rsnlen -= RSNCAPABILITIES_SIZE;
	ieptr += RSNCAPABILITIES_SIZE;
	if (rsnlen <= 0)
		return true;
	rsnpmkidlistptr = (rsnpmkidlist_t *)ieptr;
#ifndef BIG_ENDIAN_HOST
	rsnpmkidcount = rsnpmkidlistptr->count;
#else
	rsnpmkidcount = byte_swap_16(rsnpmkidlistptr->count);
#endif
	if (rsnpmkidcount == 0)
		return true;
	rsnlen -= RSNPMKIDLIST_SIZE;
	ieptr += RSNPMKIDLIST_SIZE;
	if (rsnlen < 16)
		return true;
	if (((pointer->akm & TAK_PSK) == TAK_PSK) || ((pointer->akm & TAK_PSKSHA256) == TAK_PSKSHA256))
	{
		if (memcmp(&zeroed32, ieptr, 16) == 0)
			return true;
		for (c = 0; c < 12; c++)
		{
			if (memcmp(&zeroed32, &ieptr[c], 4) == 0)
				return false;
			if (memcmp(&foxtrott, &ieptr[c], 4) == 0)
				return false;
		}
		memcpy(pointer->pmkid, ieptr, 16);
	}
	return true;
}
/*===========================================================================*/
static bool isessidvalid(int essidlen, uint8_t *essid)
{
	static int c;
	static const uint8_t foxtrott[4] = {0xff, 0xff, 0xff, 0xff};

	if (essidlen > ESSID_LEN_MAX)
		return false;
	if (essidlen == 0)
		return true;
	if (memcmp(&zeroed32, essid, essidlen) == 0)
		return true;
	if (essid[essidlen - 1] == 0)
	{
		essiderrorcount++;
		return false;
	}
	for (c = 0; c < essidlen - 4; c++)
	{
		if (memcmp(&zeroed32, &essid[c], 4) == 0)
		{
			essiderrorcount++;
			return false;
		}
		if (memcmp(&foxtrott, &essid[c], 4) == 0)
		{
			essiderrorcount++;
			return false;
		}
	}
	return true;
}
/*===========================================================================*/
static bool gettags(int infolen, uint8_t *infoptr, tags_t *pointer)
{
	static ietag_t *tagptr;
	static bool ef;

	memset(pointer, 0, TAGS_SIZE);
	ef = false;
	while (0 < infolen)
	{
		if (infolen == 4)
			return true;
		tagptr = (ietag_t *)infoptr;
		if (tagptr->len == 0)
		{
			infoptr += tagptr->len + IETAG_SIZE;
			infolen -= tagptr->len + IETAG_SIZE;
			continue;
		}
		if (tagptr->len > infolen)
			return false;
		if (tagptr->id == TAG_SSID)
		{
			if (tagptr->len > ESSID_LEN_MAX)
			{
				taglenerrorcount++;
				return false;
			}
			if (isessidvalid(tagptr->len, &tagptr->data[0]) == false)
				return false;
			{
				ef = true;
				memcpy(pointer->essid, &tagptr->data[0], tagptr->len);
				pointer->essidlen = tagptr->len;
			}
		}
		else if (tagptr->id == TAG_CHAN)
		{
			if (tagptr->len == 1)
				pointer->channel = tagptr->data[0];
		}
		else if (tagptr->id == TAG_COUNTRY)
		{
			if (tagptr->len > 2)
			{
				pointer->country[0] = tagptr->data[0];
				pointer->country[1] = tagptr->data[1];
			}
		}
		else if (tagptr->id == TAG_RSN)
		{
			if (tagptr->len >= RSNIE_LEN_MIN)
			{
				if (gettagrsn(tagptr->len, tagptr->data, pointer) == false)
					return false;
			}
		}
		else if (tagptr->id == TAG_VENDOR)
		{
			if (tagptr->len >= VENDORIE_SIZE)
			{
				if (gettagvendor(tagptr->len, tagptr->data, pointer) == false)
					return false;
			}
		}
		infoptr += tagptr->len + IETAG_SIZE;
		infolen -= tagptr->len + IETAG_SIZE;
	}
	if ((infolen != 0) && (infolen != 4) && (ef == false))
		return false;
	return true;
}
/*===========================================================================*/
static void process80211eapol_m4(uint64_t eaptimestamp, uint8_t *macap, uint8_t *macclient, uint32_t restlen, uint8_t *eapauthptr)
{
	static int c;
	static messagelist_t *pointer;
	static uint8_t *wpakptr;
	static wpakey_t *wpak;
	static eapauth_t *eapauth;
	static uint16_t authlen;
	static uint64_t eaptimegap;
	static uint8_t keyver;
	static uint64_t rc;
	static uint64_t rcgap;
	static uint8_t mpfield;

	static const uint8_t foxtrott[4] = {0xff, 0xff, 0xff, 0xff};
	eapolm4count++;
	eapolmsgcount++;
	eapauth = (eapauth_t *)eapauthptr;
	authlen = ntohs(eapauth->len);
	if (authlen + EAPAUTH_SIZE > restlen)
		return;
	if (authlen + EAPAUTH_SIZE > EAPOL_AUTHLEN_MAX)
		return;
	wpakptr = eapauthptr + EAPAUTH_SIZE;
	wpak = (wpakey_t *)wpakptr;
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if ((keyver == 0) || (keyver > 3))
	{
		eapolm4kdv0count++;
		return;
	}
	if (ntohs(wpak->wpadatalen) > (restlen - EAPAUTH_SIZE - WPAKEY_SIZE))
	{
		eapolm4errorcount++;
		return;
	}
#ifndef BIG_ENDIAN_HOST
	rc = byte_swap_64(wpak->replaycount);
#else
	rc = wpak->replaycount;
#endif
	if (memcmp(&zeroed32, wpak->keymic, 16) == 0)
	{
		eapolm4errorcount++;
		return;
	}
	for (c = 0; c < 12; c++)
	{
		if (memcmp(&zeroed32, &wpak->keymic[c], 4) == 0)
		{
			eapolm4errorcount++;
			return;
		}
		if (memcmp(&foxtrott, &wpak->keymic[c], 4) == 0)
		{
			eapolm4errorcount++;
			return;
		}
	}
	if (memcmp(&zeroed32, wpak->keyid, 8) != 0)
	{
		eapolm4errorcount++;
		return;
	}
	if (memcmp(&zeroed32, wpak->nonce, 32) == 0)
	{
		eapolm4zeroedcount++;
		return;
	}
	if ((memcmp(&fakenonce1, wpak->nonce, 32) == 0) && (rc == 17))
		return;
	if ((memcmp(&fakenonce2, wpak->nonce, 32) == 0) && (rc == 17))
		return;
	pointer = messagelist + MESSAGELIST_MAX;
	memset(pointer, 0, MESSAGELIST_SIZE);
	pointer->timestamp = eaptimestamp;
	pointer->eapolmsgcount = eapolmsgcount;
	memcpy(pointer->client, macclient, 6);
	memcpy(pointer->ap, macap, 6);
	pointer->message = HS_M4;
	pointer->rc = rc;
	memcpy(pointer->nonce, wpak->nonce, 32);
	if (pointer->eapauthlen > EAPOL_AUTHLEN_MAX)
		return;
	pointer->eapauthlen = authlen + EAPAUTH_SIZE;
	memcpy(pointer->eapol, eapauthptr, pointer->eapauthlen);

	// Loop through the messagelist
	for (pointer = messagelist; pointer < messagelist + MESSAGELIST_MAX; pointer++)
	{
		if ((pointer->message & HS_M3) == HS_M3)
		{
			if (memcmp(pointer->client, macclient, 6) != 0)
				continue;
			if (memcmp(pointer->ap, macap, 6) != 0)
				continue;
			if (pointer->rc >= rc)
				rcgap = pointer->rc - rc;
			else
				rcgap = rc - pointer->rc;
			if (rcgap > rcgapmax)
				rcgapmax = rcgap;
			if (rcgap > ncvalue)
				continue;
			if (eaptimestamp > pointer->timestamp)
				eaptimegap = eaptimestamp - pointer->timestamp;
			else
				eaptimegap = pointer->timestamp - eaptimestamp;
			mpfield = ST_M34E4;
			if (eaptimegap > eaptimegapmax)
				eaptimegapmax = eaptimegap;
			if (eaptimegap <= eapoltimeoutvalue)
				addhandshake(eaptimegap, rcgap, messagelist + MESSAGELIST_MAX, pointer, keyver, mpfield);
		}
		if ((pointer->message & HS_M1) != HS_M1)
			continue;
		if (memcmp(pointer->client, macclient, 6) != 0)
			continue;
		if (memcmp(pointer->ap, macap, 6) != 0)
			continue;
		if (pointer->rc >= rc - 1)
			rcgap = pointer->rc - rc + 1;
		else
			rcgap = rc + 1 - pointer->rc;
		if (pointer->rc != myaktreplaycount)
		{
			if (rcgap > rcgapmax)
				rcgapmax = rcgap;
		}
		if (rcgap > ncvalue)
			continue;
		if (eaptimestamp > pointer->timestamp)
			eaptimegap = eaptimestamp - pointer->timestamp;
		else
			eaptimegap = pointer->timestamp - eaptimestamp;
		mpfield = ST_M14E4;
		if (myaktreplaycount > 0)
		{
			if (pointer->rc == myaktreplaycount)
				continue;
		}
		if (eaptimegap > eaptimegapmax)
			eaptimegapmax = eaptimegap;
		if (eaptimegap <= eapoltimeoutvalue)
			addhandshake(eaptimegap, rcgap, messagelist + MESSAGELIST_MAX, pointer, keyver, mpfield);
	}
	qsort(messagelist, MESSAGELIST_MAX + 1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
	return;
}
/*===========================================================================*/
static void process80211eapol_m3(uint64_t eaptimestamp, uint8_t *macclient, uint8_t *macap, uint32_t restlen, uint8_t *eapauthptr)
{
	static int c;
	static messagelist_t *pointer;
	static messagelist_t *pointerakt;
	static uint8_t *wpakptr;
	static wpakey_t *wpak;
	static eapauth_t *eapauth;
	static uint16_t authlen;
	static uint64_t eaptimegap;
	static uint8_t keyver;
	static uint64_t rc;
	static uint64_t rcgap;
	static uint8_t mpfield;

	static const uint8_t foxtrott[4] = {0xff, 0xff, 0xff, 0xff};

	eapolm3count++;
	eapolmsgcount++;
	pointerakt = messagelist + MESSAGELIST_MAX;
	eapauth = (eapauth_t *)eapauthptr;
	authlen = ntohs(eapauth->len);
	if (authlen > restlen)
		return;
	wpakptr = eapauthptr + EAPAUTH_SIZE;
	wpak = (wpakey_t *)wpakptr;
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if ((keyver == 0) || (keyver > 3))
	{
		eapolm3kdv0count++;
		return;
	}
	if (ntohs(wpak->wpadatalen) > (restlen - EAPAUTH_SIZE - WPAKEY_SIZE))
	{
		eapolm3errorcount++;
		return;
	}
#ifndef BIG_ENDIAN_HOST
	rc = byte_swap_64(wpak->replaycount);
#else
	rc = wpak->replaycount;
#endif
	if (memcmp(&zeroed32, wpak->keymic, 16) == 0)
	{
		eapolm3errorcount++;
		return;
	}
	for (c = 0; c < 12; c++)
	{
		if (memcmp(&zeroed32, &wpak->keymic[c], 4) == 0)
		{
			eapolm3errorcount++;
			return;
		}
		if (memcmp(&foxtrott, &wpak->keymic[c], 4) == 0)
		{
			eapolm3errorcount++;
			return;
		}
	}
	if (memcmp(&zeroed32, wpak->keyid, 8) != 0)
	{
		eapolm3errorcount++;
		return;
	}
	memset(pointerakt, 0, MESSAGELIST_SIZE);
	pointerakt->timestamp = eaptimestamp;
	pointerakt->eapolmsgcount = eapolmsgcount;
	memcpy(pointerakt->client, macclient, 6);
	memcpy(pointerakt->ap, macap, 6);
	pointerakt->message = HS_M3;
	pointerakt->rc = rc;
	memcpy(pointerakt->nonce, wpak->nonce, 32);
	for (pointer = messagelist; pointer < messagelist + MESSAGELIST_MAX; pointer++)
	{
		if (((pointer->message & 1) == 1) || ((pointer->message & 4) == 4))
		{
			if ((memcmp(pointer->nonce, wpak->nonce, 28) == 0) && (memcmp(&pointer->nonce[29], &wpak->nonce[29], 4) != 0))
			{
				pointer->status |= 0x80;
				pointerakt->status |= 0x80;
				if (pointer->nonce[31] != wpak->nonce[31])
					pointer->status |= 0x20;
				else if (pointer->nonce[28] != wpak->nonce[28])
					pointer->status |= 0x40;
				eapolnccount++;
			}
		}
		if ((pointer->message & HS_M2) == HS_M2)
		{
			if (memcmp(pointer->ap, macap, 6) != 0)
				continue;
			if (memcmp(pointer->client, macclient, 6) != 0)
				continue;
			if (pointer->rc >= rc - 1)
				rcgap = pointer->rc - rc + 1;
			else
				rcgap = rc + 1 - pointer->rc;
			if (pointer->rc != myaktreplaycount)
			{
				if (rcgap > rcgapmax)
					rcgapmax = rcgap;
			}
			if (rcgap > ncvalue)
				continue;
			if (eaptimestamp > pointer->timestamp)
				eaptimegap = eaptimestamp - pointer->timestamp;
			else
				eaptimegap = pointer->timestamp - eaptimestamp;
			mpfield = ST_M32E2;
			if (myaktreplaycount > 0)
			{
				if (pointer->rc == myaktreplaycount)
					continue;
			}
			if (eaptimegap > eaptimegapmax)
				eaptimegapmax = eaptimegap;
			if (eaptimegap <= eapoltimeoutvalue)
				addhandshake(eaptimegap, rcgap, pointer, messagelist + MESSAGELIST_MAX, keyver, mpfield);
		}
		if ((pointer->message & HS_M4) != HS_M4)
			continue;
		if (memcmp(pointer->ap, macap, 6) != 0)
			continue;
		if (memcmp(pointer->client, macclient, 6) != 0)
			continue;
		if (pointer->rc >= rc)
			rcgap = pointer->rc - rc;
		else
			rcgap = rc - pointer->rc;
		if (rcgap > rcgapmax)
			rcgapmax = rcgap;
		if (rcgap > ncvalue)
			continue;
		if (eaptimestamp > pointer->timestamp)
			eaptimegap = eaptimestamp - pointer->timestamp;
		else
			eaptimegap = pointer->timestamp - eaptimestamp;
		mpfield = ST_M34E4;
		if (myaktreplaycount > 0)
		{
			if (pointer->rc == myaktreplaycount)
				continue;
		}
		if (eaptimegap > eaptimegapmax)
			eaptimegapmax = eaptimegap;
		if (eaptimegap <= eapoltimeoutvalue)
			addhandshake(eaptimegap, rcgap, pointer, messagelist + MESSAGELIST_MAX, keyver, mpfield);
	}
	qsort(messagelist, MESSAGELIST_MAX + 1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
	return;
}
/*===========================================================================*/
static void process80211eapol_m2(uint64_t eaptimestamp, uint8_t *macap, uint8_t *macclient, uint32_t restlen, uint8_t *eapauthptr)
{
	static int c;
	static messagelist_t *pointer;
	static uint8_t *wpakptr;
	static wpakey_t *wpak;
	static eapauth_t *eapauth;
	static uint16_t authlen;
	static uint64_t eaptimegap;
	static uint8_t keyver;
	static uint64_t rc;
	static uint64_t rcgap;
	static uint8_t mpfield;
	static uint16_t wpainfolen;
	static tags_t tags;

	static const uint8_t foxtrott[4] = {0xff, 0xff, 0xff, 0xff};

	eapolm2count++;
	eapolmsgcount++;
	eapauth = (eapauth_t *)eapauthptr;
	authlen = ntohs(eapauth->len);
	if (authlen + EAPAUTH_SIZE > restlen)
		return;
	wpakptr = eapauthptr + EAPAUTH_SIZE;
	wpak = (wpakey_t *)wpakptr;
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if ((keyver == 0) || (keyver > 3))
	{
		eapolm2kdv0count++;
		return;
	}
	wpainfolen = ntohs(wpak->wpadatalen);
	if (wpainfolen > (restlen - EAPAUTH_SIZE - WPAKEY_SIZE))
	{
		eapolm2errorcount++;
		return;
	}
#ifndef BIG_ENDIAN_HOST
	rc = byte_swap_64(wpak->replaycount);
#else
	rc = wpak->replaycount;
#endif
	if (memcmp(&zeroed32, wpak->nonce, 32) == 0)
		return;
	if (memcmp(&zeroed32, wpak->keymic, 16) == 0)
	{
		eapolm2errorcount++;
		return;
	}
	for (c = 0; c < 12; c++)
	{
		if (memcmp(&zeroed32, &wpak->keymic[c], 4) == 0)
		{
			eapolm2errorcount++;
			return;
		}
		if (memcmp(&foxtrott, &wpak->keymic[c], 4) == 0)
		{
			eapolm2errorcount++;
			return;
		}
	}
	if (memcmp(&zeroed32, wpak->keyiv, 16) != 0)
	{
		eapolm2errorcount++;
		return;
	}
	if (wpak->keyrsc != 0)
	{
		eapolm2errorcount++;
		return;
	}
	if (memcmp(&zeroed32, wpak->keyid, 8) != 0)
	{
		eapolm2errorcount++;
		return;
	}
	if ((memcmp(&fakenonce1, wpak->nonce, 32) == 0) && (rc == 17))
		return;
	if ((memcmp(&fakenonce2, wpak->nonce, 32) == 0) && (rc == 17))
		return;
	pointer = messagelist + MESSAGELIST_MAX;
	memset(pointer, 0, MESSAGELIST_SIZE);
	pointer->timestamp = eaptimestamp;
	pointer->eapolmsgcount = eapolmsgcount;
	memcpy(pointer->client, macclient, 6);
	memcpy(pointer->ap, macap, 6);
	pointer->message = HS_M2;
	pointer->rc = rc;
	memcpy(pointer->nonce, wpak->nonce, 32);
	pointer->eapauthlen = authlen + EAPAUTH_SIZE;
	if (wpainfolen >= RSNIE_LEN_MIN)
	{
		if (gettags(wpainfolen, wpakptr + WPAKEY_SIZE, &tags) == false)
			return;
		if ((tags.akm & TAK_FT_PSK) == TAK_FT_PSK)
			eapolm2ftpskcount++;
		if (((tags.akm & TAK_PSK) != TAK_PSK) && ((tags.akm & TAK_PSKSHA256) != TAK_PSKSHA256))
		{
			if (ignoreieflag == false)
				return;
		}
		if (memcmp(&zeroed32, tags.pmkid, 16) != 0)
		{
			pointer->message |= HS_PMKID;
			memcpy(pointer->pmkid, tags.pmkid, 16);
			addpmkid(eaptimestamp, macclient, macap, tags.pmkid, PMKID_CLIENT);
		}
	}
	if (pointer->eapauthlen > EAPOL_AUTHLEN_MAX)
		return;
	memcpy(pointer->eapol, eapauthptr, pointer->eapauthlen);
	for (pointer = messagelist; pointer < messagelist + MESSAGELIST_MAX; pointer++)
	{
		if ((pointer->message & HS_M1) == HS_M1)
		{
			if (memcmp(pointer->client, macclient, 6) != 0)
				continue;
			if (memcmp(pointer->ap, macap, 6) != 0)
				continue;
			if (pointer->rc >= rc)
				rcgap = pointer->rc - rc;
			else
				rcgap = rc - pointer->rc;
			if ((rc != myaktreplaycount) && (pointer->rc != myaktreplaycount))
			{
				if (rcgap > rcgapmax)
					rcgapmax = rcgap;
			}
			if (rcgap > ncvalue)
				continue;
			if (eaptimestamp > pointer->timestamp)
				eaptimegap = eaptimestamp - pointer->timestamp;
			else
				eaptimegap = pointer->timestamp - eaptimestamp;
			mpfield = ST_M12E2;
			if (myaktreplaycount > 0)
			{
				if ((rc == myaktreplaycount) && (memcmp(&myaktanonce, pointer->nonce, 32) == 0))
				{
					eaptimegap = 0;
					mpfield |= ST_APLESS;
				}
				if (rcgap != 0)
					continue;
			}
			if (eaptimegap > eaptimegapmax)
				eaptimegapmax = eaptimegap;
			if (eaptimegap <= eapoltimeoutvalue)
			{
				if (authlen + EAPAUTH_SIZE <= EAPOL_AUTHLEN_MAX)
					addhandshake(eaptimegap, rcgap, messagelist + MESSAGELIST_MAX, pointer, keyver, mpfield);
			}
		}
		if ((pointer->message & HS_M3) != HS_M3)
			continue;
		if (memcmp(pointer->client, macclient, 6) != 0)
			continue;
		if (memcmp(pointer->ap, macap, 6) != 0)
			continue;
		if (pointer->rc >= rc + 1)
			rcgap = pointer->rc - rc - 1;
		else
			rcgap = rc + 1 - pointer->rc;
		if (rc != myaktreplaycount)
		{
			if (rcgap > rcgapmax)
				rcgapmax = rcgap;
		}
		if (rcgap > ncvalue)
			continue;
		if (eaptimestamp > pointer->timestamp)
			eaptimegap = eaptimestamp - pointer->timestamp;
		else
			eaptimegap = pointer->timestamp - eaptimestamp;
		mpfield = ST_M32E2;
		if (myaktreplaycount > 0)
		{
			if ((rc == myaktreplaycount) && (memcmp(&myaktanonce, pointer->nonce, 32) == 0))
			{
				eaptimegap = 0;
				mpfield |= ST_APLESS;
			}
			if (rcgap != 0)
				continue;
		}
		if (eaptimegap > eaptimegapmax)
			eaptimegapmax = eaptimegap;
		if (eaptimegap <= eapoltimeoutvalue)
		{
			if (authlen + EAPAUTH_SIZE <= EAPOL_AUTHLEN_MAX)
				addhandshake(eaptimegap, rcgap, messagelist + MESSAGELIST_MAX, pointer, keyver, mpfield);
		}
	}
	qsort(messagelist, MESSAGELIST_MAX + 1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
	return;
}
/*===========================================================================*/
static void process80211eapol_m1(uint64_t eaptimestamp, uint8_t *macclient, uint8_t *macap, uint8_t *macsrc, uint32_t restlen, uint8_t *eapauthptr)
{
	static int c;
	static messagelist_t *pointer;
	static uint8_t *wpakptr;
	static wpakey_t *wpak;
	static eapauth_t *eapauth;
	static uint16_t authlen;
	static pmkid_t *pmkid;
	static uint8_t keyver;
	static uint64_t rc;

	static const uint8_t foxtrott[4] = {0xff, 0xff, 0xff, 0xff};

	eapolm1count++;
	eapolmsgcount++;
	eapauth = (eapauth_t *)eapauthptr;
	authlen = ntohs(eapauth->len);
	if (authlen > restlen)
		return;
	wpakptr = eapauthptr + EAPAUTH_SIZE;
	wpak = (wpakey_t *)wpakptr;
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if ((keyver == 0) || (keyver > 3))
	{
		eapolm1kdv0count++;
		if (authlen >= (int)(WPAKEY_SIZE + PMKID_SIZE))
		{
			pmkid = (pmkid_t *)(wpakptr + WPAKEY_SIZE);
			if (pmkid->id != TAG_VENDOR)
				return;
			if ((pmkid->len == 0x14) && (pmkid->type == 0x04))
			{
				if (memcmp(&zeroed32, pmkid->pmkid, 16) == 0)
				{
					pmkiduselesscount++;
				}
				else
				{
					pmkidakmcount++;
					pmkidcount++;
				}
			}
		}
		return;
	}
	if (ntohs(wpak->wpadatalen) > (restlen - EAPAUTH_SIZE - WPAKEY_SIZE))
	{
		eapolm1errorcount++;
		return;
	}
#ifndef BIG_ENDIAN_HOST
	rc = byte_swap_64(wpak->replaycount);
#else
	rc = wpak->replaycount;
#endif
	if (wpak->keyrsc != 0)
	{
		eapolm1errorcount++;
		return;
	}
	if (memcmp(&zeroed32, wpak->keyid, 8) != 0)
	{
		eapolm1errorcount++;
		return;
	}
	if ((memcmp(&fakenonce1, wpak->nonce, 32) == 0) && (rc == 17))
		return;
	if ((memcmp(&fakenonce2, wpak->nonce, 32) == 0) && (rc == 17))
		return;
	pointer = messagelist + MESSAGELIST_MAX;
	memset(pointer, 0, MESSAGELIST_SIZE);
	pointer->timestamp = eaptimestamp;
	pointer->eapolmsgcount = eapolmsgcount;
	memcpy(pointer->client, macclient, 6);
	memcpy(pointer->ap, macap, 6);
	pointer->message = HS_M1;
	pointer->rc = rc;
	memcpy(pointer->nonce, wpak->nonce, 32);

	if ((pointer->rc == myaktreplaycount) && (memcmp(&myaktanonce, pointer->nonce, 32) == 0))
	{
		pointer->status |= ST_APLESS;
		eapolm1ancount++;
		qsort(messagelist, MESSAGELIST_MAX + 1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
		return;
	}
	if (authlen >= (int)(WPAKEY_SIZE + PMKID_SIZE))
	{
		pmkid = (pmkid_t *)(wpakptr + WPAKEY_SIZE);
		if (pmkid->id != TAG_VENDOR)
			return;
		if ((pmkid->len == 0x14) && (pmkid->type == 0x04))
		{
			pointer->message |= HS_PMKID;
			if (memcmp(&zeroed32, pmkid->pmkid, 16) == 0)
			{
				pmkiduselesscount++;
			}
			else
			{
				for (c = 0; c < 12; c++)
				{
					if (memcmp(&zeroed32, &pmkid->pmkid[c], 4) == 0)
					{
						eapolm1errorcount++;
						return;
					}
					if (memcmp(&foxtrott, &pmkid->pmkid[c], 4) == 0)
					{
						eapolm1errorcount++;
						return;
					}
				}
				memcpy(pointer->pmkid, pmkid->pmkid, 16);
				addpmkid(eaptimestamp, macclient, macsrc, pmkid->pmkid, PMKID_AP);
			}
		}
		else
			pmkiduselesscount++;
	}
	for (pointer = messagelist; pointer < messagelist + MESSAGELIST_MAX + 1; pointer++)
	{
		if (((pointer->message & HS_M1) != HS_M1) && ((pointer->message & HS_M3) != HS_M3))
			continue;
		if (memcmp(pointer->ap, macap, 6) != 0)
			continue;
		eapolm1ancount++;
		if ((memcmp(pointer->nonce, wpak->nonce, 28) == 0) && (memcmp(&pointer->nonce[28], &wpak->nonce[28], 4) != 0))
		{
			eapolnccount++;
			pointer->status |= ST_NC;
			if (pointer->nonce[31] != wpak->nonce[31])
				pointer->status |= ST_LE;
			else if (pointer->nonce[28] != wpak->nonce[28])
				pointer->status |= ST_BE;
		}
	}
	qsort(messagelist, MESSAGELIST_MAX + 1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
	return;
}
/*===========================================================================*/
static void process80211rc4key(void)
{
	eapolrc4count++;
	return;
}
/*===========================================================================*/
static void process80211eapol(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t *macsrc, uint32_t eapauthlen, uint8_t *eapauthptr)
{
	static eapauth_t *eapauth;
	static uint32_t authlen;
	static uint8_t *wpakptr;
	static wpakey_t *wpak;
	static uint16_t keyinfo;
	static uint16_t keylen;

	eapauth = (eapauth_t *)eapauthptr;
	authlen = ntohs(eapauth->len);
	if (authlen > eapauthlen)
	{
		eapolmsgerrorcount++;
		return;
	}
	wpakptr = eapauthptr + EAPAUTH_SIZE;
	wpak = (wpakey_t *)wpakptr;
	keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
	if (wpak->keydescriptor == EAP_KDT_RC4)
	{
		process80211rc4key();
		return;
	}
	else if (wpak->keydescriptor == EAP_KDT_WPA)
		eapolwpacount++;
	else if (wpak->keydescriptor == EAP_KDT_RSN)
		eapolrsncount++;
	else
		return;
	if (authlen < WPAKEY_SIZE)
	{
		eapolmsgerrorcount++;
		return;
	}
	keylen = ntohs(wpak->keylen);
	if ((keylen != 0) && (keylen != 16) && (keylen != 32))
	{
		eapolmsgerrorcount++;
		return;
	}
	if (keyinfo == 1)
		process80211eapol_m1(eaptimestamp, macto, macfm, macsrc, eapauthlen, eapauthptr);
	else if (keyinfo == 2)
	{
		if (authlen != 0x5f)
			process80211eapol_m2(eaptimestamp, macto, macfm, eapauthlen, eapauthptr);
		else
			process80211eapol_m4(eaptimestamp, macto, macfm, eapauthlen, eapauthptr);
	}
	else if (keyinfo == 3)
		process80211eapol_m3(eaptimestamp, macto, macfm, eapauthlen, eapauthptr);
	else if (keyinfo == 4)
		process80211eapol_m4(eaptimestamp, macto, macfm, eapauthlen, eapauthptr);
	return;
}
/*===========================================================================*/
static void process80211eap(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t *macsrc, uint32_t restlen, uint8_t *eapptr)
{
	static eapauth_t *eapauth;

	eapauth = (eapauth_t *)eapptr;
	if (restlen < (int)EAPAUTH_SIZE)
		return;
	if (eapauth->type == EAPOL_KEY)
	{
		process80211eapol(eaptimestamp, macto, macfm, macsrc, restlen, eapptr);
	}
	else if (eapauth->type == EAP_PACKET)
		process80211exteap(eaptimestamp, macto, macfm, restlen, eapptr);
	// else if(eapauth->type == EAPOL_ASF) process80211exteap_asf();
	// else if(eapauth->type == EAPOL_MKA) process80211exteap_mka();
	else if (eapauth->type == EAPOL_START)
	{
	}
	else if (eapauth->type == EAPOL_START)
	{
	}
	else if (eapauth->type == EAPOL_LOGOFF)
	{
	}
	return;
}
/*===========================================================================*/
static bool cleanbackmac(void)
{
	static int c;
	static maclist2_t *pointer;

	pointer = aplistptr;
	for (c = 0; c < 20; c++)
	{
		pointer--;
		if (pointer < aplist)
			return false;
		if (pointer->type != aplistptr->type)
			continue;
		if (pointer->essidlen != aplistptr->essidlen)
			continue;
		if (memcmp(pointer->addr, aplistptr->addr, 6) != 0)
			continue;
		if (memcmp(pointer->essid, aplistptr->essid, aplistptr->essidlen) != 0)
			continue;
		pointer->timestamp = aplistptr->timestamp;
		pointer->count += 1;
		pointer->status |= aplistptr->status;
		pointer->type |= aplistptr->type;
		pointer->groupcipher |= aplistptr->groupcipher;
		pointer->cipher |= aplistptr->cipher;
		pointer->akm |= aplistptr->akm;
		if (pointer->manufacturerlen == 0)
		{
			memcpy(pointer->manufacturer, aplistptr->manufacturer, aplistptr->manufacturerlen);
			pointer->manufacturerlen = aplistptr->manufacturerlen;
		}
		if (pointer->modellen == 0)
		{
			memcpy(pointer->model, aplistptr->model, aplistptr->modellen);
			pointer->modellen = aplistptr->modellen;
		}
		if (pointer->serialnumberlen == 0)
		{
			memcpy(pointer->serialnumber, aplistptr->serialnumber, aplistptr->serialnumberlen);
			pointer->serialnumberlen = aplistptr->serialnumberlen;
		}
		if (pointer->devicenamelen == 0)
		{
			memcpy(pointer->devicename, aplistptr->devicename, aplistptr->devicenamelen);
			pointer->devicenamelen = aplistptr->devicenamelen;
		}
		if (pointer->enrolleelen == 0)
		{
			memcpy(pointer->enrollee, aplistptr->enrollee, aplistptr->enrolleelen);
			pointer->enrolleelen = aplistptr->enrolleelen;
		}
		return true;
	}
	return false;
}
/*===========================================================================*/
static void process80211reassociation_req(uint64_t reassociationrequesttimestamp, uint8_t *macclient, uint8_t *macap, uint32_t reassociationrequestlen, uint8_t *reassociationrequestptr)
{
	static int clientinfolen;
	static uint8_t *clientinfoptr;
	static maclist2_t *aplistnew;
	static tags_t tags;

	reassociationrequestcount++;
	clientinfoptr = reassociationrequestptr + CAPABILITIESREQSTA_SIZE;
	clientinfolen = reassociationrequestlen - CAPABILITIESREQSTA_SIZE;
	if (clientinfolen < (int)IETAG_SIZE)
		return;
	if (gettags(clientinfolen, clientinfoptr, &tags) == false)
		return;
	if (tags.essidlen == 0)
		return;
	if (tags.essid[0] == 0)
		return;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = reassociationrequesttimestamp;
	aplistptr->count = 1;
	aplistptr->type = AP;
	memcpy(aplistptr->addr, macap, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	aplistptr->groupcipher = tags.groupcipher;
	aplistptr->cipher = tags.cipher;
	aplistptr->akm = tags.akm;
	if (ignoreieflag == true)
	{
		if (memcmp(&zeroed32, tags.pmkid, 16) != 0)
			addpmkid(reassociationrequesttimestamp, macclient, macap, tags.pmkid, PMKID_CLIENT);
	}
	else if (((tags.akm & TAK_PSK) == TAK_PSK) || ((tags.akm & TAK_PSKSHA256) == TAK_PSKSHA256))
	{
		if (memcmp(&zeroed32, tags.pmkid, 16) != 0)
			addpmkid(reassociationrequesttimestamp, macclient, macap, tags.pmkid, PMKID_CLIENT);
	}
	else if ((tags.akm & TAK_FT_PSK) == TAK_FT_PSK)
		reassociationrequestftpskcount++;

	if ((tags.akm & TAK_PSK) == TAK_PSK)
		reassociationrequestpskcount++;
	else if ((tags.akm & TAK_FT_PSK) == TAK_FT_PSK)
		reassociationrequestftpskcount++;
	else if ((tags.akm & TAK_PSKSHA256) == TAK_PSKSHA256)
		reassociationrequestpsk256count++;
	else if ((tags.akm & TAK_SAE_SHA256) == TAK_SAE_SHA256)
		reassociationrequestsae256count++;
	else if ((tags.akm & TAK_SAE_SHA384B) == TAK_SAE_SHA384B)
		reassociationrequestsae384bcount++;
	else if ((tags.akm & TAK_OWE) == TAK_OWE)
		reassociationrequestowecount++;
	if (cleanbackmac() == false)
		aplistptr++;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = reassociationrequesttimestamp;
	aplistptr->count = 1;
	aplistptr->status = ST_REASSOC_REQ;
	aplistptr->type = CLIENT;
	memcpy(aplistptr->addr, macclient, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	aplistptr->groupcipher = tags.groupcipher;
	aplistptr->cipher = tags.cipher;
	aplistptr->akm = tags.akm;
	if (cleanbackmac() == false)
		aplistptr++;
	return;
}
/*===========================================================================*/
static void process80211association_req(uint64_t associationrequesttimestamp, uint8_t *macclient, uint8_t *macap, uint32_t associationrequestlen, uint8_t *associationrequestptr)
{
	static int clientinfolen;
	static uint8_t *clientinfoptr;
	static maclist2_t *aplistnew;
	static tags_t tags;

	associationrequestcount++;
	clientinfoptr = associationrequestptr + CAPABILITIESSTA_SIZE;
	clientinfolen = associationrequestlen - CAPABILITIESSTA_SIZE;
	if (clientinfolen < (int)IETAG_SIZE)
		return;
	if (gettags(clientinfolen, clientinfoptr, &tags) == false)
		return;
	if (tags.essidlen == 0)
		return;
	if (tags.essid[0] == 0)
		return;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = associationrequesttimestamp;
	aplistptr->count = 1;
	aplistptr->status = ST_ASSOC_REQ;
	aplistptr->type = AP;
	memcpy(aplistptr->addr, macap, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	aplistptr->groupcipher = tags.groupcipher;
	aplistptr->cipher = tags.cipher;
	aplistptr->akm = tags.akm;
	if (ignoreieflag == true)
	{
		if (memcmp(&zeroed32, tags.pmkid, 16) != 0)
			addpmkid(associationrequesttimestamp, macclient, macap, tags.pmkid, PMKID_CLIENT);
	}
	else if (((tags.akm & TAK_PSK) == TAK_PSK) || ((tags.akm & TAK_PSKSHA256) == TAK_PSKSHA256))
	{
		if (memcmp(&zeroed32, tags.pmkid, 16) != 0)
			addpmkid(associationrequesttimestamp, macclient, macap, tags.pmkid, PMKID_CLIENT);
	}
	if ((tags.akm & TAK_PSK) == TAK_PSK)
		associationrequestpskcount++;
	else if ((tags.akm & TAK_FT_PSK) == TAK_FT_PSK)
		associationrequestftpskcount++;
	else if ((tags.akm & TAK_PSKSHA256) == TAK_PSKSHA256)
		associationrequestpsk256count++;
	else if ((tags.akm & TAK_SAE_SHA256) == TAK_SAE_SHA256)
		associationrequestsae256count++;
	else if ((tags.akm & TAK_SAE_SHA384B) == TAK_SAE_SHA384B)
		associationrequestsae384bcount++;
	else if ((tags.akm & TAK_OWE) == TAK_OWE)
		associationrequestowecount++;
	if (cleanbackmac() == false)
		aplistptr++;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = associationrequesttimestamp;
	aplistptr->count = 1;
	aplistptr->status = ST_ASSOC_REQ;
	aplistptr->type = CLIENT;
	memcpy(aplistptr->addr, macclient, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	aplistptr->groupcipher = tags.groupcipher;
	aplistptr->cipher = tags.cipher;
	aplistptr->akm = tags.akm;
	if (cleanbackmac() == false)
		aplistptr++;
	return;
}
/*===========================================================================*/
static inline void process80211authentication(uint8_t *macfm, uint32_t authenticationlen, uint8_t *authenticationptr)
{
	static authf_t *auth;

	authenticationcount++;
	auth = (authf_t *)authenticationptr;
	if (authenticationlen < (int)AUTHENTICATIONFRAME_SIZE)
		return;
	if (auth->algorithm == OPEN_SYSTEM)
		authopensystemcount++;
	else if (auth->algorithm == SAE)
		authseacount++;
	else if (auth->algorithm == SHARED_KEY)
		authsharedkeycount++;
	else if (auth->algorithm == FBT)
		authfbtcount++;
	else if (auth->algorithm == FILS)
		authfilscount++;
	else if (auth->algorithm == FILSPFS)
		authfilspfs++;
	else if (auth->algorithm == FILSPK)
		authfilspkcount++;
	else if (auth->algorithm == NETWORKEAP)
		authnetworkeapcount++;
	else
		authunknowncount++;
	return;
}
/*===========================================================================*/
static void process80211probe_req_direct(uint64_t proberequesttimestamp, uint8_t *macclient, uint8_t *macap, uint32_t proberequestlen, uint8_t *proberequestptr)
{
	static maclist2_t *aplistnew;
	static tags_t tags;

	proberequestdirectedcount++;
	if (proberequestlen < (int)IETAG_SIZE)
		return;
	if (gettags(proberequestlen, proberequestptr, &tags) == false)
		return;
	if (tags.essidlen == 0)
		return;
	if (tags.essid[0] == 0)
		return;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = proberequesttimestamp;
	aplistptr->count = 1;
	aplistptr->status = ST_PROBE_REQ;
	aplistptr->type = AP;
	memcpy(aplistptr->addr, macap, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	if (cleanbackmac() == false)
		aplistptr++;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = proberequesttimestamp;
	aplistptr->count = 1;
	aplistptr->status = ST_PROBE_REQ;
	aplistptr->type = CLIENT;
	memcpy(aplistptr->addr, macclient, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	if (cleanbackmac() == false)
		aplistptr++;
	return;
}
/*===========================================================================*/
static void process80211probe_req(uint64_t proberequesttimestamp, uint8_t *macclient, uint32_t proberequestlen, uint8_t *proberequestptr)
{
	static maclist2_t *aplistnew;
	static tags_t tags;

	proberequestundirectedcount++;
	if (proberequestlen < (int)IETAG_SIZE)
		return;
	if (gettags(proberequestlen, proberequestptr, &tags) == false)
		return;
	if (tags.essidlen == 0)
		return;
	if (tags.essid[0] == 0)
		return;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = proberequesttimestamp;
	aplistptr->count = 1;
	aplistptr->status = ST_PROBE_REQ;
	aplistptr->type = CLIENT;
	memcpy(aplistptr->addr, macclient, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	if (cleanbackmac() == false)
		aplistptr++;
	return;
}
/*===========================================================================*/
static void process80211probe_resp(uint64_t proberesponsetimestamp, uint8_t *macap, uint32_t proberesponselen, uint8_t *proberesponseptr)
{
	static int apinfolen;
	static maclist2_t *aplistnew;
	static uint8_t *apinfoptr;
	static tags_t tags;

	proberesponsecount++;
	apinfoptr = proberesponseptr + CAPABILITIESAP_SIZE;
	apinfolen = proberesponselen - CAPABILITIESAP_SIZE;
	if (proberesponselen < (int)IETAG_SIZE)
		return;
	if (gettags(apinfolen, apinfoptr, &tags) == false)
		return;
	if (tags.essidlen == 0)
	{
		proberesponsessidunsetcount++;
		return;
	}
	if (memcmp(&tags.essid, &zeroed32, tags.essidlen) == 0)
	{
		proberesponsessidzeroedcount++;
		return;
	}
	if (tags.essid[0] == 0)
		return;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = proberesponsetimestamp;
	aplistptr->count = 1;
	aplistptr->status = ST_PROBE_RESP;
	aplistptr->type = AP;
	memcpy(aplistptr->addr, macap, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	aplistptr->groupcipher = tags.groupcipher;
	aplistptr->cipher = tags.cipher;
	aplistptr->akm = tags.akm;
	aplistptr->manufacturerlen = tags.manufacturerlen;
	memcpy(aplistptr->manufacturer, tags.manufacturer, tags.manufacturerlen);
	aplistptr->modellen = tags.modellen;
	memcpy(aplistptr->model, tags.model, tags.modellen);
	aplistptr->serialnumberlen = tags.serialnumberlen;
	memcpy(aplistptr->serialnumber, tags.serialnumber, tags.serialnumberlen);
	aplistptr->devicenamelen = tags.devicenamelen;
	memcpy(aplistptr->devicename, tags.devicename, tags.devicenamelen);
	aplistptr->enrolleelen = tags.enrolleelen;
	memcpy(aplistptr->enrollee, tags.enrollee, tags.enrolleelen);
	if (cleanbackmac() == false)
		aplistptr++;
	return;
}
/*===========================================================================*/
static inline bool processpag(uint8_t *macap, int vendorlen, uint8_t *ieptr)
{
	static int c, p;
	static const uint8_t mac_pwag[6] =
		{
			0xde, 0xad, 0xbe, 0xef, 0xde, 0xad};

	if (ieptr[1] != 0xff)
		return false;
	if (vendorlen <= 0x78)
		return false;
	if (memcmp(&mac_pwag, macap, 6) != 0)
		return false;
	for (p = 2; p < vendorlen - 75; p++)
	{
		if (memcmp(&ieptr[p], "identity", 8) == 0)
		{
			for (c = 0; c < 64; c++)
			{
				if (!isxdigit((unsigned char)ieptr[p + 11 + c]))
					return false;
			}
			pagcount++;
			return true;
		}
	}
	return false;
}
/*===========================================================================*/
static void process80211beacon(uint64_t beacontimestamp, uint8_t *macbc, uint8_t *macap, uint32_t beaconlen, uint8_t *beaconptr)
{
	static int apinfolen;
	static uint8_t *apinfoptr;
	static maclist2_t *aplistnew;
	static tags_t tags;

	beaconcount++;
	if (memcmp(&mac_broadcast, macbc, 6) != 0)
	{
		broadcastmacerrorcount++;
		return;
	}
	apinfoptr = beaconptr + CAPABILITIESAP_SIZE;
	apinfolen = beaconlen - CAPABILITIESAP_SIZE;
	if (apinfoptr[0] == TAG_PAG)
	{
		if (processpag(macap, apinfolen, apinfoptr) == true)
			return;
	}
	if (beaconlen < (int)IETAG_SIZE)
	{
		beaconerrorcount++;
		return;
	}
	if (gettags(apinfolen, apinfoptr, &tags) == false)
	{
		beaconerrorcount++;
		if (tags.essidlen > 32)
			beaconssidoversizedcount++;
		return;
	}
	if (tags.essidlen == 0)
	{
		beaconssidunsetcount++;
		return;
	}
	if (memcmp(&tags.essid, &zeroed32, tags.essidlen) == 0)
	{
		beaconssidzeroedcount++;
		return;
	}
	if ((tags.channel > 0) && (tags.channel <= 14))
	{
		beaconchannel[0] |= GHZ24;
		beaconchannel[tags.channel]++;
	}
	if ((tags.channel > 14) && (tags.channel < CHANNEL_MAX))
	{
		beaconchannel[0] |= GHZ5;
		beaconchannel[tags.channel]++;
	}
	if (tags.essid[0] == 0)
		return;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = beacontimestamp;
	aplistptr->count = 1;
	aplistptr->status = ST_BEACON;
	aplistptr->type = AP;
	memcpy(aplistptr->addr, macap, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	aplistptr->groupcipher = tags.groupcipher;
	aplistptr->cipher = tags.cipher;
	aplistptr->akm = tags.akm;
	aplistptr->manufacturerlen = tags.manufacturerlen;
	memcpy(aplistptr->manufacturer, tags.manufacturer, tags.manufacturerlen);
	aplistptr->modellen = tags.modellen;
	memcpy(aplistptr->model, tags.model, tags.modellen);
	aplistptr->serialnumberlen = tags.serialnumberlen;
	memcpy(aplistptr->serialnumber, tags.serialnumber, tags.serialnumberlen);
	aplistptr->devicenamelen = tags.devicenamelen;
	memcpy(aplistptr->devicename, tags.devicename, tags.devicenamelen);
	aplistptr->enrolleelen = tags.enrolleelen;
	memcpy(aplistptr->enrollee, tags.enrollee, tags.enrolleelen);
	if (cleanbackmac() == false)
		aplistptr++;
	return;
}
/*===========================================================================*/
static void process80211actionmeasurement(uint64_t actiontimestamp, uint8_t *macclient, uint32_t packetlen, uint8_t *packetptr)
{
	static maclist2_t *aplistnew;
	static tags_t tags;
	static actmm_t *actmm;

	if (packetlen < ACTIONMEASUREMENTFRAME_SIZE)
		return;
	actmm = (actmm_t *)packetptr;
	if (actmm->actioncode != ACT_MM_NRREQ)
		return;
	packetlen -= (int)ACTIONMEASUREMENTFRAME_SIZE;
	packetptr += (int)ACTIONMEASUREMENTFRAME_SIZE;
	if (packetlen < (int)IETAG_SIZE)
		return;
	if (gettags(packetlen, packetptr, &tags) == false)
		return;
	if (tags.essidlen == 0)
		return;
	if (tags.essid[0] == 0)
		return;
	if (aplistptr >= aplist + maclistmax)
	{
		aplistnew = (maclist2_t *)realloc(aplist, (maclistmax + MACLIST2_MAX) * MACLIST_SIZE2);
		if (aplistnew == NULL)
		{
			printError("failed to allocate memory for internal list", 1);
			exit(EXIT_FAILURE);
		}
		aplist = aplistnew;
		aplistptr = aplistnew + maclistmax;
		maclistmax += MACLIST2_MAX;
	}
	memset(aplistptr, 0, MACLIST_SIZE2);
	aplistptr->timestamp = actiontimestamp;
	aplistptr->count = 1;
	aplistptr->status = ST_ACT_MR_REQ;
	aplistptr->type = CLIENT;
	memcpy(aplistptr->addr, macclient, 6);
	aplistptr->essidlen = tags.essidlen;
	memcpy(aplistptr->essid, tags.essid, tags.essidlen);
	if (cleanbackmac() == false)
		aplistptr++;
	actionessidcount++;
	return;
}
/*===========================================================================*/
static void process80211actionvendor(uint32_t packetlen, uint8_t *packetptr)
{
	static actvf_t *actvf;

	if (packetlen < ACTIONVENDORFRAME_SIZE)
		return;
	actvf = (actvf_t *)packetptr;
	if (memcmp(actvf->vendor, &ouiapple, 3) == 0)
		awdlcount++;
	return;
}
/*===========================================================================*/
static void process80211action(uint64_t actiontimestamp, uint8_t *macclient, uint32_t packetlen, uint8_t *packetptr)
{
	static actf_t *actf;

	if (packetlen < ACTIONFRAME_SIZE)
		return;
	actf = (actf_t *)packetptr;
	actioncount++;
	if (actf->categoriecode == CAT_VENDOR)
		process80211actionvendor(packetlen, packetptr);
	else if (actf->categoriecode == CAT_RADIO_MEASUREMENT)
		process80211actionmeasurement(actiontimestamp, macclient, packetlen, packetptr);
	return;
}
/*===========================================================================*/
static void process80211packet(uint64_t packetimestamp, uint32_t packetlen, uint8_t *packetptr)
{
	static mac_t *macfrx;
	static uint32_t payloadlen;
	static uint8_t *payloadptr;
	static uint8_t *llcptr;
	static llc_t *llc;
	static uint8_t *mpduptr;
	static mpdu_t *mpdu;

	ieee80211flag = true;

	if (packetlen < (int)MAC_SIZE_NORM)
		return;
	macfrx = (mac_t *)packetptr;

	if ((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
	{
		payloadptr = packetptr + MAC_SIZE_LONG;
		payloadlen = packetlen - MAC_SIZE_LONG;
		wdscount++;
	}
	else
	{
		payloadptr = packetptr + MAC_SIZE_NORM;
		payloadlen = packetlen - MAC_SIZE_NORM;
	}
	if (macfrx->type == IEEE80211_FTYPE_MGMT)
	{
		if (macfrx->subtype == IEEE80211_STYPE_BEACON)
			process80211beacon(packetimestamp, macfrx->addr1, macfrx->addr2, payloadlen, payloadptr);
		else if (macfrx->subtype == IEEE80211_STYPE_PROBE_RESP)
			process80211probe_resp(packetimestamp, macfrx->addr2, payloadlen, payloadptr);
		else if (macfrx->subtype == IEEE80211_STYPE_AUTH)
			process80211authentication(macfrx->addr2, payloadlen, payloadptr);
		else if (macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ)
			process80211association_req(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
		else if (macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ)
			process80211reassociation_req(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
		else if (macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
			if (memcmp(&mac_broadcast, macfrx->addr1, 6) == 0)
				process80211probe_req(packetimestamp, macfrx->addr2, payloadlen, payloadptr);
			else
				process80211probe_req_direct(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
		}
		else if (macfrx->subtype == IEEE80211_STYPE_ACTION)
			process80211action(packetimestamp, macfrx->addr2, payloadlen, payloadptr);
		else if (macfrx->subtype == IEEE80211_STYPE_DEAUTH)
			deauthenticationcount++;
		else if (macfrx->subtype == IEEE80211_STYPE_DISASSOC)
			disassociationcount++;
		else if (macfrx->subtype == IEEE80211_STYPE_MGTRESERVED)
			mgtreservedcount++;
	}
	else if (macfrx->type == IEEE80211_FTYPE_DATA)
	{
		if ((macfrx->subtype & IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
		{
			payloadptr += QOS_SIZE;
			payloadlen -= QOS_SIZE;
		}
		if (payloadlen < (int)LLC_SIZE)
			return;
		llcptr = payloadptr;
		llc = (llc_t *)llcptr;
		if (((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
			process80211eap(packetimestamp, macfrx->addr1, macfrx->addr2, macfrx->addr3, payloadlen - LLC_SIZE, payloadptr + LLC_SIZE);
		}
		else if (((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
			processipv4(packetimestamp, payloadlen - LLC_SIZE, payloadptr + LLC_SIZE);
		}
		else if (((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
			processipv6(packetimestamp, payloadlen - LLC_SIZE, payloadptr + LLC_SIZE);
		}
		else if (macfrx->prot == 1)
		{
			mpduptr = payloadptr;
			mpdu = (mpdu_t *)mpduptr;
			if (((mpdu->keyid >> 5) & 1) == 1)
				wpaenccount++;
			else if (((mpdu->keyid >> 5) & 1) == 0)
				wepenccount++;
		}
	}
	return;
}
/*===========================================================================*/
static void processethernetpacket(uint64_t timestamp, uint32_t caplen, uint8_t *packetptr)
{
	static eth2_t *eth2;

	if (caplen < LLC_SIZE)
		return;
	eth2 = (eth2_t *)packetptr;
	if (ntohs(eth2->ether_type) == LLC_TYPE_IPV4)
	{
		processipv4(timestamp, caplen - ETH2_SIZE, packetptr + ETH2_SIZE);
	}
	else if (ntohs(eth2->ether_type) == LLC_TYPE_IPV6)
	{
		processipv6(timestamp, caplen - ETH2_SIZE, packetptr + ETH2_SIZE);
	}
	/*
	if(ntohs(eth2->ether_type) == LLC_TYPE_AUTH)
		{
		process80211networkauthentication(tv_sec, tv_usec, caplen, eth2->addr1, eth2->addr2, packet_ptr);
		}
	*/
	return;
}
/*===========================================================================*/
static void processlobapacket(uint64_t timestamp, uint32_t caplen, uint8_t *packetptr)
{
	static loba_t *loba;
	if (caplen < LOBA_SIZE)
		return;
	loba = (loba_t *)packetptr;
#ifdef BIG_ENDIAN_HOST
	loba->family = byte_swap_32(loba->family);
#endif
	if (loba->family == LOBA_IPV4)
		processipv4(timestamp, caplen - LOBA_SIZE, packetptr + LOBA_SIZE);
	else if (loba->family == LOBA_IPV624)
		processipv6(timestamp, caplen - LOBA_SIZE, packetptr + LOBA_SIZE);
	else if (loba->family == LOBA_IPV628)
		processipv6(timestamp, caplen - LOBA_SIZE, packetptr + LOBA_SIZE);
	else if (loba->family == LOBA_IPV630)
		processipv6(timestamp, caplen - LOBA_SIZE, packetptr + LOBA_SIZE);
	return;
}
/*===========================================================================*/
static void getradiotapfield(uint16_t rthlen, uint32_t caplen, uint8_t *capptr)
{
	static int i;
	static uint16_t pf;
	static rth_t *rth;
	static uint32_t *pp;

	frequency = 0;
	rth = (rth_t *)capptr;
	pf = RTH_SIZE;
	if ((rth->it_present & IEEE80211_RADIOTAP_CHANNEL) != IEEE80211_RADIOTAP_CHANNEL)
		return;
	if ((rth->it_present & IEEE80211_RADIOTAP_EXT) == IEEE80211_RADIOTAP_EXT)
	{
		pp = (uint32_t *)capptr;
		for (i = 2; i < rthlen / 4; i++)
		{
#ifdef BIG_ENDIAN_HOST
			pp[i] = byte_swap_32(pp[i]);
#endif
			pf += 4;
			if ((pp[i] & IEEE80211_RADIOTAP_EXT) != IEEE80211_RADIOTAP_EXT)
				break;
		}
	}
	if ((rth->it_present & IEEE80211_RADIOTAP_TSFT) == IEEE80211_RADIOTAP_TSFT)
	{
		if ((pf % 8) != 0)
			pf += 4;
		pf += 8;
	}
	if ((rth->it_present & IEEE80211_RADIOTAP_FLAGS) == IEEE80211_RADIOTAP_FLAGS)
		pf += 1;
	if ((rth->it_present & IEEE80211_RADIOTAP_RATE) == IEEE80211_RADIOTAP_RATE)
		pf += 1;
	if ((rth->it_present & IEEE80211_RADIOTAP_CHANNEL) == IEEE80211_RADIOTAP_CHANNEL)
	{
		if (pf > caplen)
			return;
		if ((pf % 2) != 0)
			pf += 1;
		frequency = (capptr[pf + 1] << 8) + capptr[pf];
		usedfrequency[frequency] += 1;
		if (frequency == 2484)
		{
			interfacechannel = 14;
			band24count++;
		}
		else if (frequency < 2484)
		{
			interfacechannel = (frequency - 2407) / 5;
			band24count++;
		}

		else if (frequency >= 4910 && frequency <= 4980)
		{
			interfacechannel = (frequency - 4000) / 5;
			band5count++;
		}
		else if (frequency < 5925)
		{
			interfacechannel = (frequency - 5000) / 5;
			band5count++;
		}
		else if (frequency == 5935)
		{
			interfacechannel = 2;
			band6count++;
		}
		else if ((frequency >= 5955) && (frequency <= 7115))
		{
			interfacechannel = (frequency - 5950) / 5;
			band6count++;
		}
		pf += 4;
	}
	if ((rth->it_present & IEEE80211_RADIOTAP_FHSS) == IEEE80211_RADIOTAP_FHSS)
	{
		if ((pf % 2) != 0)
			pf += 1;
		pf += 2;
	}
	if ((rth->it_present & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == IEEE80211_RADIOTAP_DBM_ANTSIGNAL)
	{
		if (pf > caplen)
			return;
		rssi = capptr[pf];
	}
	return;
}
/*===========================================================================*/
static void processlinktype(uint64_t captimestamp, uint32_t linktype, uint32_t caplen, uint8_t *capptr)
{
	static uint8_t cs;
	static uint32_t p;
	static rth_t *rth;
	static uint32_t packetlen;
	static uint8_t *packetptr;
	static ppi_t *ppi;
	static prism_t *prism;
	static avs_t *avs;
	static fcs_t *fcs;
	static uint32_t crc;

	rssi = 0;
	interfacechannel = 0;

	if (captimestamp < captimestampold)
		sequenceerrorcount++;
	captimestampold = captimestamp;
	if (timestampmin == 0)
		timestampmin = captimestamp;
	if (timestampmin > captimestamp)
		timestampmin = captimestamp;
	if (timestampmax < captimestamp)
		timestampmax = captimestamp;
	if (captimestamp == 0)
	{
		captimestamp = timestampstart;
		timestampstart += (eapoltimeoutvalue - 2);
		zeroedtimestampcount++;
	}
	if (linktype == DLT_IEEE802_11_RADIO)
	{
		if (caplen < RTH_SIZE)
		{
			pcapreaderrors++;
			radiotaperrorcount++;
			return;
		}
		rth = (rth_t *)capptr;
#ifdef BIG_ENDIAN_HOST
		rth->it_len = byte_swap_16(rth->it_len);
		rth->it_present = byte_swap_32(rth->it_present);
#endif
		if (rth->it_len > caplen)
		{
			pcapreaderrors++;
			radiotaperrorcount++;
			return;
		}
		if (rth->it_version != 0)
		{
			pcapreaderrors++;
			radiotaperrorcount++;
			return;
		}
		getradiotapfield(rth->it_len, caplen, capptr);
		packetlen = caplen - rth->it_len;
		packetptr = capptr + rth->it_len;
	}
	else if (linktype == DLT_IEEE802_11)
	{
		packetptr = capptr;
		packetlen = caplen;
	}
	else if (linktype == DLT_PPI)
	{
		if (caplen < PPI_SIZE)
		{
			pcapreaderrors++;
			printError("failed to read ppi header", 0);
			return;
		}
		ppi = (ppi_t *)capptr;
#ifdef BIG_ENDIAN_HOST
		ppi->pph_len = byte_swap_16(ppi->pph_len);
#endif
		if (ppi->pph_len > caplen)
		{
			pcapreaderrors++;
			printError("failed to read ppi header", 0);
			return;
		}
		packetlen = caplen - ppi->pph_len;
		packetptr = capptr + ppi->pph_len;
	}
	else if (linktype == DLT_PRISM_HEADER)
	{
		if (caplen < PRISM_SIZE)
		{
			pcapreaderrors++;
			printError("failed to read prism header", 0);
			return;
		}
		prism = (prism_t *)capptr;
#ifdef BIG_ENDIAN_HOST
		prism->msgcode = byte_swap_32(prism->msgcode);
		prism->msglen = byte_swap_32(prism->msglen);
		prism->frmlen.data = byte_swap_32(prism->frmlen.data);
#endif
		if (prism->msglen > caplen)
		{
			if (prism->frmlen.data > caplen)
			{
				pcapreaderrors++;
				printError("failed to read prism header", 0);
				return;
			}
			prism->msglen = caplen - prism->frmlen.data;
		}
		packetlen = caplen - prism->msglen;
		packetptr = capptr + prism->msglen;
	}
	else if (linktype == DLT_IEEE802_11_RADIO_AVS)
	{
		if (caplen < AVS_SIZE)
		{
			pcapreaderrors++;
			printError("failed to read avs header", 0);
			return;
		}
		avs = (avs_t *)capptr;
#ifdef BIG_ENDIAN_HOST
		avs->len = byte_swap_32(avs->len);
#endif
		if (avs->len > caplen)
		{
			pcapreaderrors++;
			printError("failed to read avs header", 0);
			return;
		}
		packetlen = caplen - avs->len;
		packetptr = capptr + avs->len;
	}
	else if (linktype == DLT_EN10MB)
	{
		if (caplen < ETH2_SIZE)
		{
			pcapreaderrors++;
			printError("failed to read ethernet header", 0);
			return;
		}
		processethernetpacket(captimestamp, caplen, capptr);
		return;
	}
	else if (linktype == DLT_NULL)
	{
		if (caplen < LOBA_SIZE)
		{
			pcapreaderrors++;
			printError("failed to read loopback header", 0);
			return;
		}
		processlobapacket(captimestamp, caplen, capptr);
		return;
	}
	else
	{
		static char *error[300];
		snprintf(error, 299, "unsupported network type %d", linktype);
		printError(error, 0);
		return;
	}

	if (packetlen < 4)
	{
		pcapreaderrors++;
		printError("failed to read packet", 0);
		return;
	}
	fcs = (fcs_t *)(packetptr + packetlen - 4);
	crc = fcscrc32check(packetptr, packetlen - 4);
#ifdef BIG_ENDIAN_HOST
	crc = byte_swap_32(crc);
#endif
	if (crc == fcs->fcs)
	{
		fcsframecount++;
		packetlen -= 4;
	}
	process80211packet(captimestamp, packetlen, packetptr);
	return;
}

/*===========================================================================*/
void processcap(int fd, char *eigenname, char *pcaporgname, char *pcapinname)
{
	static unsigned int res;
	static off_t resseek;
	static pcap_hdr_t pcapfhdr;
	static pcaprec_hdr_t pcaprhdr;
	static uint64_t timestampcap;
	static uint8_t packet[MAXPACPSNAPLEN];

	ancientdumpfileformat = true;
	iface = 1;
	res = read(fd, &pcapfhdr, PCAPHDR_SIZE);
	if (res != PCAPHDR_SIZE)
	{
		pcapreaderrors++;
		printError("failed to read pcap header", 1);
		return;
	}

#ifdef BIG_ENDIAN_HOST
	pcapfhdr.magic_number = byte_swap_32(pcapfhdr.magic_number);
	pcapfhdr.version_major = byte_swap_16(pcapfhdr.version_major);
	pcapfhdr.version_minor = byte_swap_16(pcapfhdr.version_minor);
	pcapfhdr.thiszone = byte_swap_32(pcapfhdr.thiszone);
	pcapfhdr.sigfigs = byte_swap_32(pcapfhdr.sigfigs);
	pcapfhdr.snaplen = byte_swap_32(pcapfhdr.snaplen);
	pcapfhdr.network = byte_swap_32(pcapfhdr.network);
#endif

	if (pcapfhdr.magic_number == PCAPMAGICNUMBERBE)
	{
		pcapfhdr.magic_number = byte_swap_32(pcapfhdr.magic_number);
		pcapfhdr.version_major = byte_swap_16(pcapfhdr.version_major);
		pcapfhdr.version_minor = byte_swap_16(pcapfhdr.version_minor);
		pcapfhdr.thiszone = byte_swap_32(pcapfhdr.thiszone);
		pcapfhdr.sigfigs = byte_swap_32(pcapfhdr.sigfigs);
		pcapfhdr.snaplen = byte_swap_32(pcapfhdr.snaplen);
		pcapfhdr.network = byte_swap_32(pcapfhdr.network);
		endianness = 1;
	}

	versionmajor = pcapfhdr.version_major;
	versionminor = pcapfhdr.version_minor;

	dltlinktype[0] = pcapfhdr.network;
	if (pcapfhdr.version_major != PCAP_MAJOR_VER)
	{
		pcapreaderrors++;
		printError("unsupported major pcap version", 1);
		return;
	}
	if (pcapfhdr.version_minor != PCAP_MINOR_VER)
	{
		pcapreaderrors++;
		printError("unsupported minor pcap version", 1);
		return;
	}
	if (pcapfhdr.snaplen > MAXPACPSNAPLEN)
	{
		pcapreaderrors++;
		static char *error[300];
		snprintf(error, 299, "detected oversized snaplen (%d)", pcapfhdr.snaplen);
		printError(error, 0);
	}

	while (1)
	{
		res = read(fd, &pcaprhdr, PCAPREC_SIZE);
		if (res == 0)
			break;
		if (res != PCAPREC_SIZE)
		{
			pcapreaderrors++;
			static char *error[300];
			snprintf(error, 299, "failed to read pcap packet header for packet %ld", rawpacketcount);
			printError(error, 0);
			break;
		}

#ifdef BIG_ENDIAN_HOST
		pcaprhdr.ts_sec = byte_swap_32(pcaprhdr.ts_sec);
		pcaprhdr.ts_usec = byte_swap_32(pcaprhdr.ts_usec);
		pcaprhdr.incl_len = byte_swap_32(pcaprhdr.incl_len);
		pcaprhdr.orig_len = byte_swap_32(pcaprhdr.orig_len);
#endif
		if (endianness == 1)
		{
			pcaprhdr.ts_sec = byte_swap_32(pcaprhdr.ts_sec);
			pcaprhdr.ts_usec = byte_swap_32(pcaprhdr.ts_usec);
			pcaprhdr.incl_len = byte_swap_32(pcaprhdr.incl_len);
			pcaprhdr.orig_len = byte_swap_32(pcaprhdr.orig_len);
		}
		if (pcaprhdr.incl_len > pcapfhdr.snaplen)
		{
			pcapreaderrors++;
		}
		if (pcaprhdr.incl_len < MAXPACPSNAPLEN)
		{
			rawpacketcount++;
			res = read(fd, &packet, pcaprhdr.incl_len);
			if (res != pcaprhdr.incl_len)
			{
				pcapreaderrors++;
				static char *error[300];
				snprintf(error, 299, "failed to read packet %ld", rawpacketcount);
				printError(error, 0);
				break;
			}
		}
		else
		{
			skippedpacketcount++;
			resseek = lseek(fd, pcaprhdr.incl_len, SEEK_CUR);
			if (resseek < 0)
			{
				pcapreaderrors++;
				printError("failed to set file pointer", 0);
				break;
			}
			continue;
		}
		if (pcaprhdr.incl_len > 0)
		{
			timestampcap = ((uint64_t)pcaprhdr.ts_sec * 1000000) + pcaprhdr.ts_usec;
			timestampcap *= 1000;
			processlinktype(timestampcap, pcapfhdr.network, pcaprhdr.incl_len, packet);
		}
	}

	cleanupmac();
	outputdeviceinfolist();
	outputwpalists();
	outputwordlists();
	return;
}
/*===========================================================================*/
static int pcapngoptionwalk(uint32_t blocktype, uint8_t *optr, int restlen)
{
	static int csn, csc, pn;
	static int padding;
	static option_header_t *option;

	while (0 < restlen)
	{
		option = (option_header_t *)optr;
#ifdef BIG_ENDIAN_HOST
		option->option_code = byte_swap_16(option->option_code);
		option->option_length = byte_swap_16(option->option_length);
#endif
		if (endianness == 1)
		{
			option->option_code = byte_swap_16(option->option_code);
			option->option_length = byte_swap_16(option->option_length);
		}
		if (option->option_code == SHB_EOC)
			return 0;
		padding = 0;
		if (option->option_length > OPTIONLEN_MAX)
			return option->option_length;
		if ((option->option_length % 4))
			padding = 4 - (option->option_length % 4);
		if (option->option_code == SHB_HARDWARE)
		{
			if (option->option_length < OPTIONLEN_MAX)
			{
				memset(&pcapnghwinfo, 0, OPTIONLEN_MAX);
				memcpy(&pcapnghwinfo, option->data, option->option_length);
			}
		}
		else if (option->option_code == SHB_OS)
		{
			if (option->option_length < OPTIONLEN_MAX)
			{
				memset(&pcapngosinfo, 0, OPTIONLEN_MAX);
				memcpy(&pcapngosinfo, option->data, option->option_length);
			}
		}
		else if (option->option_code == SHB_USER_APPL)
		{
			if (option->option_length < OPTIONLEN_MAX)
			{
				memset(&pcapngapplinfo, 0, OPTIONLEN_MAX);
				memcpy(&pcapngapplinfo, option->data, option->option_length);
			}
		}
		else if (option->option_code == IF_MACADDR)
		{
			if (option->option_length == 6)
			{
				memset(&pcapngdeviceinfo, 0, 6);
				memcpy(&pcapngdeviceinfo, option->data, 6);
			}
		}
		else if (option->option_code == IF_TSRESOL)
		{
			if (option->option_length == 1)
				pcapngtimeresolution = option->data[0];
		}
		else if (option->option_code == SHB_CUSTOM_OPT)
		{
			if (option->option_length > 40)
			{
				if ((memcmp(&option->data[0], &hcxmagic, 4) == 0) && (memcmp(&option->data[4], &hcxmagic, 32) == 0))
					restlen = pcapngoptionwalk(blocktype, optr + OH_SIZE + 36, option->option_length - 36);
				else if ((memcmp(&option->data[1], &hcxmagic, 4) == 0) && (memcmp(&option->data[5], &hcxmagic, 32) == 0))
					restlen = pcapngoptionwalk(blocktype, optr + OH_SIZE + 1 + 36, option->option_length - 36);
			}
		}
		else if (option->option_code == OPTIONCODE_MACORIG)
		{
			if (option->option_length == 6)
			{
				memset(&pcapngdeviceinfo, 0, 6);
				memcpy(&pcapngdeviceinfo, option->data, 6);
			}
		}
		else if (option->option_code == OPTIONCODE_MACAP)
		{
			if (option->option_length == 6)
				memcpy(&myaktap, &option->data, 6);
		}
		else if (option->option_code == OPTIONCODE_RC)
		{
			if (option->option_length == 8)
			{
				myaktreplaycount = option->data[0x07] & 0xff;
				myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x06] & 0xff);
				myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x05] & 0xff);
				myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x04] & 0xff);
				myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x03] & 0xff);
				myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x02] & 0xff);
				myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x01] & 0xff);
				myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x00] & 0xff);
				if (endianness == 1)
					myaktreplaycount = byte_swap_64(myaktreplaycount);
			}
		}
		else if (option->option_code == OPTIONCODE_ANONCE)
		{
			if (option->option_length == 32)
				memcpy(&myaktanonce, &option->data, 32);
		}
		else if (option->option_code == OPTIONCODE_MACCLIENT)
		{
			if (option->option_length == 6)
				memcpy(&myaktclient, &option->data, 6);
		}
		else if (option->option_code == OPTIONCODE_SNONCE)
		{
			if (option->option_length == 32)
				memcpy(&myaktsnonce, &option->data, 32);
		}
		else if (option->option_code == OPTIONCODE_WEAKCANDIDATE)
		{
			if (option->option_length < 64)
				memcpy(&pcapngweakcandidate, &option->data, option->option_length);
		}
		optr += option->option_length + padding + OH_SIZE;
		restlen -= option->option_length + padding + OH_SIZE;
	}
	return 0;
}
/*===========================================================================*/
void processpcapng(int fd, char *eigenname, char *pcaporgname, char *pcapinname)
{
	static unsigned int res;
	static off_t fdsize;
	static off_t aktseek;
	static off_t resseek;
	static uint32_t snaplen;
	static uint32_t blocktype;
	static uint32_t blocklen;
	static uint32_t blockmagic;
	static uint64_t timestamppcapng;
	static int padding;
	static block_header_t *pcapngbh;
	static section_header_block_t *pcapngshb;
	static interface_description_block_t *pcapngidb;
	static packet_block_t *pcapngpb;
	static enhanced_packet_block_t *pcapngepb;
	static custom_block_t *pcapngcb;

	static int interfaceid[MAX_INTERFACE_ID];
	static uint8_t pcpngblock[2 * MAXPACPSNAPLEN];
	static uint8_t packet[MAXPACPSNAPLEN];

	magicblockcount = 0;
	ancientdumpfileformat = false;
	iface = 0;
	nmealen = 0;
	memset(&interfaceid, 0, sizeof(int) * MAX_INTERFACE_ID);
	fdsize = lseek(fd, 0, SEEK_END);
	if (fdsize < 0)
	{
		pcapreaderrors++;
		printError("failed to get file size", 0);
		return;
	}

	aktseek = lseek(fd, 0L, SEEK_SET);
	if (aktseek < 0)
	{
		pcapreaderrors++;
		printError("failed to set file pointer", 0);
		return;
	}

	snaplen = 0;
	memset(&packet, 0, MAXPACPSNAPLEN);
	while (1)
	{
		aktseek = lseek(fd, 0, SEEK_CUR);
		if (aktseek < 0)
		{
			pcapreaderrors++;
			printError("failed to set file pointer", 0);
			break;
		}
		res = read(fd, &pcpngblock, BH_SIZE);
		if (res == 0)
		{
			break;
		}
		if (res != BH_SIZE)
		{
			pcapreaderrors++;
			printError("failed to read block header\n", 0);
			break;
		}
		pcapngbh = (block_header_t *)pcpngblock;
		blocktype = pcapngbh->block_type;
		blocklen = pcapngbh->total_length;
		blockmagic = pcapngbh->byte_order_magic;
#ifdef BIG_ENDIAN_HOST
		blocktype = byte_swap_32(blocktype);
		blocklen = byte_swap_32(blocklen);
		blockmagic = byte_swap_32(blockmagic);
#endif
		if (blocktype == PCAPNGBLOCKTYPE)
		{
			if (blockmagic == PCAPNGMAGICNUMBERBE)
				endianness = 1;
		}
		if (endianness == 1)
		{
			blocktype = byte_swap_32(blocktype);
			blocklen = byte_swap_32(blocklen);
		}
		if ((blocklen > (2 * MAXPACPSNAPLEN)) || ((blocklen % 4) != 0))
		{
			pcapreaderrors++;
			printError("failed to read pcapng block header", 0);
			break;
		}
		resseek = lseek(fd, aktseek, SEEK_SET);
		if (resseek < 0)
		{
			pcapreaderrors++;
			printError("failed to set file pointer", 0);
			break;
		}
		res = read(fd, &pcpngblock, blocklen);
		if ((res < BH_SIZE) || (res != blocklen))
		{
			pcapreaderrors++;
			printError("failed to read pcapng block header", 0);
			break;
		}
		if (memcmp(&pcpngblock[4], &pcpngblock[blocklen - 4], 4) != 0)
		{
			pcapreaderrors++;
			printError("failed to read pcapng block header", 0);
			break;
		}
		if (blocktype == PCAPNGBLOCKTYPE)
		{
			pcapngshb = (section_header_block_t *)pcpngblock;
#ifdef BIG_ENDIAN_HOST
			pcapngshb->major_version = byte_swap_16(pcapngshb->major_version);
			pcapngshb->minor_version = byte_swap_16(pcapngshb->minor_version);
			pcapngshb->section_length = byte_swap_64(pcapngshb->section_length);
#endif
			if (endianness == 1)
			{
				pcapngshb->major_version = byte_swap_16(pcapngshb->major_version);
				pcapngshb->minor_version = byte_swap_16(pcapngshb->minor_version);
				pcapngshb->section_length = byte_swap_64(pcapngshb->section_length);
			}
			versionmajor = pcapngshb->major_version;
			versionminor = pcapngshb->minor_version;
			if (pcapngshb->major_version != PCAPNG_MAJOR_VER)
			{
				pcapreaderrors++;
				printError("unsupported major pcapng version", 0);
				break;
			}
			if (pcapngshb->minor_version != PCAPNG_MINOR_VER)
			{
				pcapreaderrors++;
				printError("unsupported minor pcapng version", 0);
				break;
			}
			if (pcapngoptionwalk(blocktype, pcapngshb->data, blocklen - SHB_SIZE) != 0)
				pcapreaderrors++;
		}
		else if (blocktype == IDBID)
		{
			pcapngidb = (interface_description_block_t *)pcpngblock;
#ifdef BIG_ENDIAN_HOST
			pcapngidb->linktype = byte_swap_16(pcapngidb->linktype);
			pcapngidb->snaplen = byte_swap_32(pcapngidb->snaplen);
#endif
			if (endianness == 1)
			{
				pcapngidb->linktype = byte_swap_16(pcapngidb->linktype);
				pcapngidb->snaplen = byte_swap_32(pcapngidb->snaplen);
			}
			snaplen = pcapngidb->snaplen;
			if (pcapngoptionwalk(blocktype, pcapngidb->data, blocklen - IDB_SIZE) != 0)
				pcapreaderrors++;
			if (snaplen > MAXPACPSNAPLEN)
			{
				pcapreaderrors++;
				static char *error[300];
				snprintf(error, 299, "detected oversized snaplen (%d)", snaplen);
				printError(error, 0);
			}
			if (iface >= MAX_INTERFACE_ID)
			{
				pcapreaderrors++;
				static char *error[300];
				snprintf(error, 299, "maximum of supported interfaces reached: %d", iface);
				printError(error, 0);
				continue;
			}
			dltlinktype[iface] = pcapngidb->linktype;
			timeresolval[iface] = pcapngtimeresolution;
			iface++;
		}
		else if (blocktype == PBID)
		{
			pcapngpb = (packet_block_t *)pcpngblock;
#ifdef BIG_ENDIAN_HOST
			pcapngpb->caplen = byte_swap_32(pcapngpb->caplen);
#endif
			if (endianness == 1)
				pcapngpb->caplen = byte_swap_32(pcapngpb->caplen);
			timestamppcapng = 0;
			if (pcapngpb->caplen > MAXPACPSNAPLEN)
			{
				pcapreaderrors++;
				static char *error[300];
				snprintf(error, 299, "caplen > MAXSNAPLEN (%d > %d)", pcapngpb->caplen, MAXPACPSNAPLEN);
				printError(error, 0);
				continue;
			}
			if (pcapngpb->caplen > blocklen)
			{
				static char *error[300];
				snprintf(error, 299, "caplen > blocklen (%d > %d)", pcapngpb->caplen, blocklen);
				printError(error, 0);
				pcapreaderrors++;
				continue;
			}
			rawpacketcount++;
			processlinktype(timestamppcapng, dltlinktype[0], pcapngpb->caplen, pcapngpb->data);
		}
		else if (blocktype == SPBID)
			continue;
		else if (blocktype == NRBID)
			continue;
		else if (blocktype == ISBID)
			continue;
		else if (blocktype == EPBID)
		{
			pcapngepb = (enhanced_packet_block_t *)pcpngblock;
#ifdef BIG_ENDIAN_HOST
			pcapngepb->interface_id = byte_swap_32(pcapngepb->interface_id);
			pcapngepb->timestamp_high = byte_swap_32(pcapngepb->timestamp_high);
			pcapngepb->timestamp_low = byte_swap_32(pcapngepb->timestamp_low);
			pcapngepb->caplen = byte_swap_32(pcapngepb->caplen);
			pcapngepb->len = byte_swap_32(pcapngepb->len);
#endif
			if (endianness == 1)
			{
				pcapngepb->interface_id = byte_swap_32(pcapngepb->interface_id);
				pcapngepb->timestamp_high = byte_swap_32(pcapngepb->timestamp_high);
				pcapngepb->timestamp_low = byte_swap_32(pcapngepb->timestamp_low);
				pcapngepb->caplen = byte_swap_32(pcapngepb->caplen);
				pcapngepb->len = byte_swap_32(pcapngepb->len);
			}
			if (pcapngepb->interface_id >= iface)
			{
				pcapreaderrors++;
				static char *error[300];
				snprintf(error, 299, "maximum of supported interfaces reached: %d", iface);
				printError(error, 0);
				continue;
			}
			timestamppcapng = pcapngepb->timestamp_high;
			timestamppcapng = (timestamppcapng << 32) + pcapngepb->timestamp_low;

			if (timeresolval[pcapngepb->interface_id] == TSRESOL_USEC)
			{
				timestamppcapng = pcapngepb->timestamp_high;
				timestamppcapng = (timestamppcapng << 32) + pcapngepb->timestamp_low;
				timestamppcapng *= 1000;
			}
			if (pcapngepb->caplen != pcapngepb->len)
			{
				pcapreaderrors++;
				static char *error[300];
				snprintf(error, 299, "caplen != len (%d != %d)", pcapngepb->caplen, pcapngepb->len);
				printError(error, 0);
				continue;
			}
			if (pcapngepb->caplen > MAXPACPSNAPLEN)
			{
				pcapreaderrors++;
				static char *error[300];
				snprintf(error, 299, "caplen > MAXSNAPLEN (%d > %d)", pcapngepb->caplen, MAXPACPSNAPLEN);
				printError(error, 0);
				continue;
			}
			if (pcapngepb->caplen > blocklen)
			{
				pcapreaderrors++;
				static char *error[300];
				snprintf(error, 299, "caplen > blocklen (%d > %d)", pcapngepb->caplen, blocklen);
				printError(error, 0);
				continue;
			}
			rawpacketcount++;
			processlinktype(timestamppcapng, dltlinktype[pcapngepb->interface_id], pcapngepb->caplen, pcapngepb->data);
			padding = 0;
			if ((pcapngepb->caplen % 4) != 0)
				padding = 4 - (pcapngepb->caplen % 4);
			if (pcapngoptionwalk(blocktype, pcapngepb->data + pcapngepb->caplen + padding, blocklen - EPB_SIZE - pcapngepb->caplen - padding) != 0)
				pcapreaderrors++;
		}
		else if (blocktype == CBID)
		{
			pcapngcb = (custom_block_t *)pcpngblock;
			if (blocklen < CB_SIZE)
			{
				skippedpacketcount++;
				continue;
			}
			if (memcmp(pcapngcb->pen, &hcxmagic, 4) != 0)
			{
				skippedpacketcount++;
				continue;
			}
			if (memcmp(pcapngcb->hcxm, &hcxmagic, 32) != 0)
			{
				skippedpacketcount++;
				continue;
			}
			magicblockcount++;
			if (pcapngoptionwalk(blocktype, pcapngcb->data, blocklen - CB_SIZE) != 0)
				pcapreaderrors++;
		}
		else
		{
			skippedpacketcount++;
		}
	}

	cleanupmac();
	outputdeviceinfolist();
	outputwpalists();
	outputwordlists();
	return;
}
/*===========================================================================*/
static bool processcapfile(char *eigenname, char *pcapinname)
{
	static int resseek;
	static uint32_t magicnumber;
	static char *pcapnameptr;

	pcapnameptr = pcapinname;

	jtrbasenamedeprecated = pcapinname;
	if (fd_pcap == -1)
	{
		printError("failed to open file", 1);
		exit(EXIT_FAILURE);
	}
	magicnumber = getmagicnumber(fd_pcap);
	if (magicnumber == 0)
	{
		printError("Incorrect PCAP Magic - exiting", 1);
		exit(EXIT_FAILURE);
	}
	resseek = lseek(fd_pcap, 0L, SEEK_SET);
	if (resseek < 0)
	{
		pcapreaderrors++;
		printError("failed to set file pointer", 1);
		exit(EXIT_FAILURE);
	}
	if (magicnumber == PCAPNGBLOCKTYPE)
	{
		if (initlists() == true)
		{
			processpcapng(fd_pcap, eigenname, pcapinname, pcapnameptr);
			pcapngstat++;
			close(fd_pcap);
			closelists();
		}
	}
	else if ((magicnumber == PCAPMAGICNUMBER) || (magicnumber == PCAPMAGICNUMBERBE))
	{
		if (magicnumber == PCAPMAGICNUMBERBE)
			endianness = 1;
		if (initlists() == true)
		{
			processcap(fd_pcap, eigenname, pcapinname, pcapnameptr);
			capstat++;
			close(fd_pcap);
			closelists();
		}
	}
	else
	{
		printError("unsupported dump file format", 1);
		exit(EXIT_FAILURE);
	}

	/* if (pcaptempnameptr != NULL)
		remove(pcaptempnameptr); */

	return true;
}
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
{
	static char *ptr;

	ptr = buffer + len - 1;
	while (len)
	{
		if (*ptr != '\n')
			break;
		*ptr-- = 0;
		len--;
	}
	while (len)
	{
		if (*ptr != '\r')
			break;
		*ptr-- = 0;
		len--;
	}
	return len;
}
/*---------------------------------------------------------------------------*/
static inline int fgetline(FILE *inputstream, size_t size, char *buffer)
{
	static size_t len;
	static char *buffptr;

	if (feof(inputstream))
		return -1;
	buffptr = fgets(buffer, size, inputstream);
	if (buffptr == NULL)
		return -1;
	len = strlen(buffptr);
	len = chop(buffptr, len);
	return len;
}
/*===========================================================================*/

/*===========================================================================*/
static bool evpdeinitwpa(void)
{
	if (ctxhmac != NULL)
	{
		EVP_MAC_CTX_free(ctxhmac);
		EVP_MAC_free(hmac);
	}
	if (ctxcmac != NULL)
	{
		EVP_MAC_CTX_free(ctxcmac);
		EVP_MAC_free(cmac);
	}
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	return true;
}
/*===========================================================================*/
static bool evpinitwpa(void)
{
	static unsigned long opensslversion;

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	opensslversion = OpenSSL_version_num();
	opensslversionmajor = (opensslversion & 0x10000000L) >> 28;
	opensslversionminor = (opensslversion & 0x01100000L) >> 20;

	hmac = NULL;
	ctxhmac = NULL;
	cmac = NULL;
	ctxcmac = NULL;

	hmac = EVP_MAC_fetch(NULL, "hmac", NULL);
	if (hmac == NULL)
		return false;
	cmac = EVP_MAC_fetch(NULL, "cmac", NULL);
	if (cmac == NULL)
		return false;

	char md5[] = "md5";
	paramsmd5[0] = OSSL_PARAM_construct_utf8_string("digest", md5, 0);
	paramsmd5[1] = OSSL_PARAM_construct_end();

	char sha1[] = "sha1";
	paramssha1[0] = OSSL_PARAM_construct_utf8_string("digest", sha1, 0);
	paramssha1[1] = OSSL_PARAM_construct_end();

	char sha256[] = "sha256";
	paramssha256[0] = OSSL_PARAM_construct_utf8_string("digest", sha256, 0);
	paramssha256[1] = OSSL_PARAM_construct_end();

	char aes[] = "aes-1280-cbc";
	paramsaes128[0] = OSSL_PARAM_construct_utf8_string("cipher", aes, 0);
	paramsaes128[1] = OSSL_PARAM_construct_end();

	ctxhmac = EVP_MAC_CTX_new(hmac);
	if (ctxhmac == NULL)
		return false;
	ctxcmac = EVP_MAC_CTX_new(cmac);
	if (ctxcmac == NULL)
		return false;
	return true;
}
/*===========================================================================*/

void write_archive(const char *outname, char **filename, int files_count)
{
	struct archive *a;
	struct archive_entry *entry;
	struct stat st;
	char buff[8192];
	int len;
	int tarfd;

	a = archive_write_new();
	archive_write_add_filter_gzip(a);
	archive_write_set_format_pax_restricted(a);
	archive_write_open_filename(a, outname);

	for (int i = 0; i <= files_count - 1; i++)
	{
		stat(filename[i], &st);
		entry = archive_entry_new();
		archive_entry_set_pathname(entry, filename[i]);
		archive_entry_set_size(entry, st.st_size);
		archive_entry_set_filetype(entry, AE_IFREG);
		archive_entry_set_perm(entry, 0644);
		archive_write_header(a, entry);
		tarfd = open(filename[i], O_RDONLY);
		len = read(tarfd, buff, sizeof(buff));
		while (len > 0)
		{
			archive_write_data(a, buff, len);
			len = read(tarfd, buff, sizeof(buff));
		}
		close(tarfd);
		archive_entry_free(entry);
	}
	archive_write_close(a);
	archive_write_free(a);
}

static inline void send_lists(void)
{

	cJSON *data = cJSON_CreateObject();
	cJSON *pcaptool = cJSON_CreateObject();
	char *string = NULL;
	static time_t tvmin;
	static time_t tvmax;
	static char timestringmin[32];
	static char timestringmax[32];

	// Capture Interface
	cJSON_AddItemToObject(pcaptool, "interface_id", cJSON_CreateNumber(iface));

	cJSON_AddItemToObject(pcaptool, "raw_packet_count", cJSON_CreateNumber(rawpacketcount));

	cJSON_AddItemToObject(pcaptool, "skipped_packet_count", cJSON_CreateNumber(skippedpacketcount));

	cJSON_AddItemToObject(pcaptool, "fcs_frame_count", cJSON_CreateNumber(fcsframecount));

	cJSON_AddItemToObject(pcaptool, "band24_count", cJSON_CreateNumber(band24count));

	cJSON_AddItemToObject(pcaptool, "band5_count", cJSON_CreateNumber(band5count));

	cJSON_AddItemToObject(pcaptool, "band6_count", cJSON_CreateNumber(band6count));

	cJSON_AddItemToObject(pcaptool, "wds_count", cJSON_CreateNumber(wdscount));

	// Frames containing device info
	cJSON_AddItemToObject(pcaptool, "device_info_count", cJSON_CreateNumber(deviceinfocount));
	// Frames Containing ESSID
	cJSON_AddItemToObject(pcaptool, "essid_count", cJSON_CreateNumber(essidcount));
	// Frames containing Beacons
	cJSON_AddItemToObject(pcaptool, "beacon_count", cJSON_CreateNumber(beaconcount));

	// Becaons per channel
	int beacon24 = 0;
	if ((beaconchannel[0] & GHZ24) == GHZ24)
	{
		for (int i = 1; i <= 14; i++)
		{
			if (beaconchannel[i] != 0)
				beacon24 += beaconchannel[i];
		}
	}
	cJSON_AddItemToObject(pcaptool, "beacon_count_24", cJSON_CreateNumber(beacon24));
	int beacon5 = 0;
	if ((beaconchannel[0] & GHZ5) == GHZ5)
	{
		for (int i = 15; i <= CHANNEL_MAX; i++)
		{
			if (beaconchannel[i] != 0)
				beacon5 += beaconchannel[i];
		}
	}
	cJSON_AddItemToObject(pcaptool, "beacon_count_5", cJSON_CreateNumber(beacon5));

	cJSON_AddItemToObject(pcaptool, "probe_request_undirected_count", cJSON_CreateNumber(proberequestundirectedcount));
	cJSON_AddItemToObject(pcaptool, "probe_request_directed_count", cJSON_CreateNumber(proberequestdirectedcount));
	cJSON_AddItemToObject(pcaptool, "probe_response_count", cJSON_CreateNumber(proberesponsecount));
	cJSON_AddItemToObject(pcaptool, "deauthentication_count", cJSON_CreateNumber(deauthenticationcount));
	cJSON_AddItemToObject(pcaptool, "disassociation_count", cJSON_CreateNumber(disassociationcount));
	cJSON_AddItemToObject(pcaptool, "authentication_count", cJSON_CreateNumber(authenticationcount));
	cJSON_AddItemToObject(pcaptool, "auth_open_system_count", cJSON_CreateNumber(authopensystemcount));
	cJSON_AddItemToObject(pcaptool, "auth_shared_key_count", cJSON_CreateNumber(authsharedkeycount));
	cJSON_AddItemToObject(pcaptool, "association_request_count", cJSON_CreateNumber(associationrequestcount));

	// Usernames captured
	cJSON_AddItemToObject(pcaptool, "username_count", cJSON_CreateNumber(usernamecount));

	// Identities captured
	cJSON_AddItemToObject(pcaptool, "identity_count", cJSON_CreateNumber(identitycount));

	// Total EAPOL M1
	cJSON_AddItemToObject(pcaptool, "eapol_m1_count", cJSON_CreateNumber(eapolm1count));
	// Total EAPOL M2
	cJSON_AddItemToObject(pcaptool, "eapol_m2_count", cJSON_CreateNumber(eapolm2count));
	// Total EAPOL M3
	cJSON_AddItemToObject(pcaptool, "eapol_m3_count", cJSON_CreateNumber(eapolm3count));
	// Total EAPOL M4
	cJSON_AddItemToObject(pcaptool, "eapol_m4_count", cJSON_CreateNumber(eapolm4count));
	// Total EAPOL M4 (Zeroed)
	cJSON_AddItemToObject(pcaptool, "eapol_m4_zeroed_count", cJSON_CreateNumber(eapolm4zeroedcount));
	// Total EAPOL Pairs
	cJSON_AddItemToObject(pcaptool, "eapol_mp_count", cJSON_CreateNumber(eapolmpcount));
	// Total EAPOL from Zeroes PSK (Not converted)
	cJSON_AddItemToObject(pcaptool, "zeroed_eapol_psk_count", cJSON_CreateNumber(zeroedeapolpskcount));
	// Total EAPOL from Zeroes PMK (Not converted)
	cJSON_AddItemToObject(pcaptool, "zeroed_eapol_pmk_count", cJSON_CreateNumber(zeroedeapolpmkcount));
	// Total EAPOL Pairs (Best)
	cJSON_AddItemToObject(pcaptool, "eapol_mp_bestcount", cJSON_CreateNumber(eapolmpbestcount));
	// Total EAPOL Rogue Pairs (From Rogue AP)
	cJSON_AddItemToObject(pcaptool, "eapol_apless_count", cJSON_CreateNumber(eapolaplesscount));
	// Total EAPOL Written (RC Checked)
	cJSON_AddItemToObject(pcaptool, "eapol_written_count", cJSON_CreateNumber(eapolwrittencount));
	// Total EAPOL Written (RC Not Checked)
	cJSON_AddItemToObject(pcaptool, "eapolnc_written_count", cJSON_CreateNumber(eapolncwrittencount));
	// Total RSN PMKID (Best)
	cJSON_AddItemToObject(pcaptool, "pmkid_best_count", cJSON_CreateNumber(pmkidbestcount));
	// Total RSN PMKID (Rogue)
	cJSON_AddItemToObject(pcaptool, "pmkid_rogue_count", cJSON_CreateNumber(pmkidroguecount));
	// Total RSN PMKID Written
	cJSON_AddItemToObject(pcaptool, "pmkid_written_count", cJSON_CreateNumber(pmkidwrittenhcount));
	// Total RSN Client PMKID Written (Possible MESH or Repeater PMKIDs)
	cJSON_AddItemToObject(pcaptool, "pmkid_client_written_count", cJSON_CreateNumber(pmkidclientwrittenhcount));
	// Total Number of hashes written
	int totalwritten = (eapolwrittencount + eapolncwrittencount + eapolwrittenhcpxcountdeprecated + eapolncwrittenhcpxcountdeprecated + eapolwrittenhcpcountdeprecated + eapolwrittenjcountdeprecated + pmkidwrittenhcount + pmkidwrittenjcountdeprecated + pmkidwrittencountdeprecated + eapmd5writtencount + eapmd5johnwrittencount + eapleapwrittencount + eapmschapv2writtencount + tacacspwrittencount);
	cJSON_AddItemToObject(pcaptool, "total_written", cJSON_CreateNumber(totalwritten));

	tvmin = timestampmin / 1000000000;
	strftime(timestringmin, 32, "%m.%d.%Y %H:%M:%S", localtime(&tvmin));
	tvmax = timestampmax / 1000000000;
	time_t timestamptotal = tvmax - tvmin;
	strftime(timestringmax, 32, "%m.%d.%Y %H:%M:%S", localtime(&tvmax));

	cJSON_AddItemToObject(pcaptool, "timestamp_minimum", cJSON_CreateString(timestringmin));
	cJSON_AddItemToObject(pcaptool, "timestamp_maximum", cJSON_CreateString(timestringmax));
	cJSON_AddItemToObject(pcaptool, "timestamp_total", cJSON_CreateNumber(timestamptotal));

	cJSON_AddItemToObject(pcaptool, "22000_exported", cJSON_CreateNumber(pmkidfile));
	cJSON_AddItemToObject(pcaptool, "22000client_exported", cJSON_CreateNumber(pmkidclientfile));
	cJSON_AddItemToObject(pcaptool, "essid_exported", cJSON_CreateNumber(essidfile));
	cJSON_AddItemToObject(pcaptool, "identity_exported", cJSON_CreateNumber(identityfile));
	cJSON_AddItemToObject(pcaptool, "username_exported", cJSON_CreateNumber(usernamefile));
	cJSON_AddItemToObject(pcaptool, "deviceinfo_exported", cJSON_CreateNumber(deviceinfofile));
	cJSON_AddItemToObject(pcaptool, "pcapng_exported", cJSON_CreateNumber(pcapng_written));
	cJSON_AddItemToObject(pcaptool, "files_compressed", cJSON_CreateNumber(data_compressed));

	// add "pcaptool" tool to data.
	cJSON_AddItemToObject(data, "pcaptool", pcaptool);

	if (clearScreen)
	{
		string = cJSON_Print(data);
	}
	else
	{
		string = cJSON_PrintUnformatted(data);
	}
	cJSON_Delete(data);
	if (string)
	{
		printf("%s\n", string);
		cJSON_free(string);
	}
}

static void printError(char *error, bool fatal)
{
	cJSON *data = cJSON_CreateObject();
	cJSON *dumptool = cJSON_CreateObject();
	char *string = NULL;

	cJSON_AddStringToObject(dumptool, "message", error);
	cJSON_AddBoolToObject(dumptool, "fatal", fatal);

	cJSON_AddItemToObject(data, "ERROR", dumptool);

	if (clearScreen)
	{
		string = cJSON_Print(data);
	}
	else
	{
		string = cJSON_PrintUnformatted(data);
	}
	cJSON_Delete(data);
	if (string)
	{
		printf("%s\n", string);
	}
	cJSON_free(string);
}

/*===========================================================================*/
int pcapngtool(const char *prefixname, uint8_t *pcap_buffer, size_t len, bool writePcapNG, bool tarFiles, bool clear)
{
	static int exitcode;

	static char *pcapngoutname;
	static char *pmkideapoloutname;
	static char *pmkidclientoutname;
	static char *usernameoutname;
	static char *essidoutname;
	static char *identityoutname;
	static char *deviceinfooutname;
	static char *tarfileoutname;
	static char *argsfileoutname;
	static char *gzfileoutname;

	static const char *pcapngsuffix = ".pcapng";
	static const char *pmkideapolsuffix = ".22000";
	static const char *pmkidclientsuffix = ".22000client";
	static const char *essidsuffix = ".essid";
	static const char *identitysuffix = ".identity";
	static const char *usernamesuffix = ".username";
	static const char *deviceinfosuffix = ".deviceinfo";
	static const char *argsfilesuffix = ".args";
	static const char *tarfilesuffix = ".tar.gz";

	static char pcapngprefix[PATH_MAX];
	static char pmkideapolprefix[PATH_MAX];
	static char pmkidclientprefix[PATH_MAX];
	static char essidprefix[PATH_MAX];
	static char identityprefix[PATH_MAX];
	static char usernameprefix[PATH_MAX];
	static char deviceinfoprefix[PATH_MAX];
	static char argsfileprefix[PATH_MAX];
	static char tarfileprefix[PATH_MAX];

	struct timeval tv;
	static struct stat statinfo;

	clearScreen = clear;

	// Create fd in memory.
	int fd = memfd_create("pcap_buffer", 0);

	if (fd != -1)
	{
		if (write(fd, pcap_buffer, len) == -1)
			error("write()");

		off_t location = lseek(fd, 0, SEEK_CUR);
		location = lseek(fd, 0, SEEK_SET);
	}

	fd_pcap = fd;

	exitcode = EXIT_SUCCESS;
	addtimestampflag = false;
	ignoreieflag = false;
	donotcleanflag = false;
	eapoltimeoutvalue = EAPOLTIMEOUT;
	ncvalue = NONCEERRORCORRECTION;
	essidsvalue = ESSIDSMAX;

	char *prefixoutname = prefixname;
	if (strlen(prefixoutname) > PREFIX_BUFFER_MAX)
	{
		static char *error[300];
		snprintf(error, 299, "prefix must be < %d", PATH_MAX - 12);
		printError(error, 1);
		exit(EXIT_FAILURE);
	}

	fh_pmkideapol = NULL;
	fh_pmkideapolclient = NULL;
	fh_essid = NULL;
	fh_deviceinfo = NULL;
	fh_identity = NULL;
	fh_username = NULL;

	gzipstat = 0;
	capstat = 0;
	pcapngstat = 0;

	gettimeofday(&tv, NULL);
	timestampstart = ((uint64_t)tv.tv_sec * 1000000) + tv.tv_usec;

	// some openssl shit idk
	if (evpinitwpa() == false)
		exit(EXIT_FAILURE);

	// set filenames prefix+suffix
	if (prefixoutname != NULL)
	{
		strncpy(pcapngprefix, prefixoutname, PREFIX_BUFFER_MAX);
		strncat(pcapngprefix, pcapngsuffix, PREFIX_BUFFER_MAX);
		pcapngoutname = pcapngprefix;

		strncpy(pmkideapolprefix, prefixoutname, PREFIX_BUFFER_MAX);
		strncat(pmkideapolprefix, pmkideapolsuffix, PREFIX_BUFFER_MAX);
		pmkideapoloutname = pmkideapolprefix;

		strncpy(pmkidclientprefix, prefixoutname, PREFIX_BUFFER_MAX);
		strncat(pmkidclientprefix, pmkidclientsuffix, PREFIX_BUFFER_MAX);
		pmkidclientoutname = pmkidclientprefix;

		strncpy(essidprefix, prefixoutname, PREFIX_BUFFER_MAX);
		strncat(essidprefix, essidsuffix, PREFIX_BUFFER_MAX);
		essidoutname = essidprefix;

		strncpy(identityprefix, prefixoutname, PREFIX_BUFFER_MAX);
		strncat(identityprefix, identitysuffix, PREFIX_BUFFER_MAX);
		identityoutname = identityprefix;

		strncpy(usernameprefix, prefixoutname, PREFIX_BUFFER_MAX);
		strncat(usernameprefix, usernamesuffix, PREFIX_BUFFER_MAX);
		usernameoutname = usernameprefix;

		strncpy(deviceinfoprefix, prefixoutname, PREFIX_BUFFER_MAX);
		strncat(deviceinfoprefix, deviceinfosuffix, PREFIX_BUFFER_MAX);
		deviceinfooutname = deviceinfoprefix;

		strncpy(argsfileprefix, prefixoutname, PREFIX_BUFFER_MAX);
		strncat(argsfileprefix, argsfilesuffix, PREFIX_BUFFER_MAX);
		argsfileoutname = argsfileprefix;

		strncpy(tarfileprefix, prefixoutname, PREFIX_BUFFER_MAX);
		strncat(tarfileprefix, tarfilesuffix, PREFIX_BUFFER_MAX);
		gzfileoutname = tarfileprefix;
	}

	// Write data to pcapng.
	if (writePcapNG)
	{
		FILE *pcapfile;
		pcapfile = fopen(pcapngoutname, "w+");
		fwrite(pcap_buffer, len, 1, pcapfile);
		fclose(pcapfile);
		pcapng_written = true;
	}

	// Open outputfiles
	if (pmkideapoloutname != NULL)
	{
		if ((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)
		{
			static char *error[300];
			snprintf(error, 299, "error opening file %s: %s", pmkideapoloutname, strerror(errno));
			printError(error, 1);
			exit(EXIT_FAILURE);
		}
	}
	if (pmkidclientoutname != NULL)
	{
		if ((fh_pmkideapolclient = fopen(pmkidclientoutname, "a")) == NULL)
		{
			static char *error[300];
			snprintf(error, 299, "error opening file %s: %s\n", pmkidclientoutname, strerror(errno));
			printError(error, 1);
			exit(EXIT_FAILURE);
		}
	}
	if (essidoutname != NULL)
	{
		if ((fh_essid = fopen(essidoutname, "a")) == NULL)
		{
			static char *error[300];
			snprintf(error, 299, "error opening file %s: %s\n", essidoutname, strerror(errno));
			printError(error, 1);
			exit(EXIT_FAILURE);
		}
	}
	if (identityoutname != NULL)
	{
		if ((fh_identity = fopen(identityoutname, "a")) == NULL)
		{
			static char *error[300];
			snprintf(error, 299, "error opening file %s: %s\n", identityoutname, strerror(errno));
			printError(error, 1);
			exit(EXIT_FAILURE);
		}
	}
	if (usernameoutname != NULL)
	{
		if ((fh_username = fopen(usernameoutname, "a")) == NULL)
		{
			static char *error[300];
			snprintf(error, 299, "error opening file %s: %s\n", usernameoutname, strerror(errno));
			printError(error, 1);
			exit(EXIT_FAILURE);
		}
	}
	if (deviceinfooutname != NULL)
	{
		if ((fh_deviceinfo = fopen(deviceinfooutname, "a")) == NULL)
		{
			static char *error[300];
			snprintf(error, 299, "error opening file %s: %s\n", deviceinfooutname, strerror(errno));
			printError(error, 1);
			exit(EXIT_FAILURE);
		}
	}

	// process data
	if (processcapfile("net-nomad", "memory") == false)
		exitcode = EXIT_FAILURE;

	///// PROCESSING COMPLETE, SHUTERDOWN ////

	// Close files descriptors
	if (fh_pmkideapol != NULL)
		fclose(fh_pmkideapol);
	if (fh_pmkideapolclient != NULL)
		fclose(fh_pmkideapolclient);
	if (fh_essid != NULL)
		fclose(fh_essid);
	if (fh_identity != NULL)
		fclose(fh_identity);
	if (fh_username != NULL)
		fclose(fh_username);
	if (fh_deviceinfo != NULL)
		fclose(fh_deviceinfo);
	if (fd != NULL)
		close(fd);

	// Remove empty files, but remember if we made them (for tar)

	if (pmkideapoloutname != NULL)
	{
		if (stat(pmkideapoloutname, &statinfo) == 0)
		{
			if (statinfo.st_size == 0)
			{
				remove(pmkideapoloutname);
			}
			else
			{
				pmkidfile = true;
			}
		}
	}
	if (pmkidclientoutname != NULL)
	{
		if (stat(pmkidclientoutname, &statinfo) == 0)
		{
			if (statinfo.st_size == 0)
			{
				remove(pmkidclientoutname);
			}
			else
			{
				pmkidclientfile = true;
			}
		}
	}
	if (essidoutname != NULL)
	{
		if (stat(essidoutname, &statinfo) == 0)
		{
			if (statinfo.st_size == 0)
			{
				remove(essidoutname);
			}
			else
			{
				essidfile = true;
			}
		}
	}
	if (identityoutname != NULL)
	{
		if (stat(identityoutname, &statinfo) == 0)
		{
			if (statinfo.st_size == 0)
			{
				remove(identityoutname);
			}
			else
			{
				identityfile = true;
			}
		}
	}
	if (usernameoutname != NULL)
	{
		if (stat(usernameoutname, &statinfo) == 0)
		{
			if (statinfo.st_size == 0)
			{
				remove(usernameoutname);
			}
			else
			{
				usernamefile = true;
			}
		}
	}
	if (deviceinfooutname != NULL)
	{
		if (stat(deviceinfooutname, &statinfo) == 0)
		{
			if (statinfo.st_size == 0)
			{
				remove(deviceinfooutname);
			}
			else
			{
				deviceinfofile = true;
			}
		}
	}
	if (argsfileoutname != NULL)
	{
		if (stat(argsfileoutname, &statinfo) == 0)
		{
			if (statinfo.st_size == 0)
			{
				remove(argsfileoutname);
			}
			else
			{
				argsfile = true;
			}
		}
	}

	// Tarfiles

	if (tarFiles)
	{
		char **files;
		files = (char **)malloc(sizeof(char **) * 10);
		int files_total = 0;

		if (pmkidfile)
		{
			files[files_total] = (char *)malloc(sizeof(char) * (strlen(pmkideapoloutname) + 1));
			strcpy(files[files_total], pmkideapoloutname);
			// printf("%d: %s\n", files_total, files[files_total]);
			files_total += 1;
		}
		if (pmkidclientfile)
		{
			files[files_total] = (char *)malloc(sizeof(char) * (strlen(pmkidclientoutname) + 1));
			strcpy(files[files_total], pmkidclientoutname);
			// printf("%d: %s\n", files_total, files[files_total]);
			files_total += 1;
		}
		if (essidfile)
		{
			files[files_total] = (char *)malloc(sizeof(char) * (strlen(essidoutname) + 1));
			strcpy(files[files_total], essidoutname);
			// printf("%d: %s\n", files_total, files[files_total]);
			files_total += 1;
		}
		if (identityfile)
		{
			files[files_total] = (char *)malloc(sizeof(char) * (strlen(identityoutname) + 1));
			strcpy(files[files_total], identityoutname);
			// printf("%d: %s\n", files_total, files[files_total]);
			files_total += 1;
		}
		if (usernamefile)
		{
			files[files_total] = (char *)malloc(sizeof(char) * (strlen(usernameoutname) + 1));
			strcpy(files[files_total], usernameoutname);
			// printf("%d: %s\n", files_total, files[files_total]);
			files_total += 1;
		}
		if (deviceinfofile)
		{
			files[files_total] = (char *)malloc(sizeof(char) * (strlen(deviceinfooutname) + 1));
			strcpy(files[files_total], deviceinfooutname);
			// printf("%d: %s\n", files_total, files[files_total]);
			files_total += 1;
		}
		if (argsfile)
		{
			files[files_total] = (char *)malloc(sizeof(char) * (strlen(argsfileoutname) + 1));
			strcpy(files[files_total], argsfileoutname);
			// printf("%d: %s\n", files_total, files[files_total]);
			files_total += 1;
		}
		if (pcapng_written)
		{
			files[files_total] = (char *)malloc(sizeof(char) * (strlen(pcapngoutname) + 1));
			strcpy(files[files_total], pcapngoutname);
			// printf("%d: %s\n", files_total, files[files_total]);
			files_total += 1;
		}

		write_archive(gzfileoutname, files, files_total);
		data_compressed = true;
		for (int i = 0; i <= files_total - 1; i++)
		{
			remove(files[i]);
			free(files[i]);
		}
		free(files);
	}

	if (evpdeinitwpa() == false)
		exit(EXIT_FAILURE);

	send_lists();
	return exitcode;
}
/*===========================================================================*/
