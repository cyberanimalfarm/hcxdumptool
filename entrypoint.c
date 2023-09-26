int entrypoint(char* iname)
{
	// Setup options
	static u8 exiteapolflag = 0; // Did we exit because of eapol needs being met? (damn i hope so)
	static u8 exitsigtermflag = 0; // Did we exit because of SIGTERM?
	static u8 exittotflag = 0; // Did we exit because of Timeout Timer?
	static u8 exitwatchdogflag = 0; // Did we exit because of "watchdog" (wtf is this)
	static u8 exiterrorflag = 0; // Did we exit because of error count?
	static struct timespec tspecifo, tspeciforem;
	static char *bpfname = NULL; // TODO: actually generate the BPF using libpcap
	static char *essidlistname = NULL; // ESSID list approved for targeting unassociated clients (We could use this, if we can get a list of probes from a target from kismet?)
	static char *userchannellistname = NULL; // List of user channels to scan (Likely our priority use-case because we should have the channel from Kismet)
	static char *userfrequencylistname = NULL; // List of user freqs to scan (Likely not used)
	static char *pcapngoutname = NULL; // Pass to entrypoint (standard timestamp format, probably... or even better... ditch and keep the data in memory for passing directly to pcapngtool?

	ifaktindex = if_nametoindex(iname)
	strncpy(ifaktname, iname, IF_NAMESIZE - 1);

	optind = 1;
	optopt = 0;
	while ((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
		switch (auswahl)
		{
			case HCX_IFNAME:
				if ((ifaktindex = if_nametoindex(optarg)) == 0)
				{
					perror("failed to get interface index");
					exit(EXIT_FAILURE);
				}
				strncpy(ifaktname, optarg, IF_NAMESIZE - 1);
				break;

			case HCX_BPF:
				bpfname = optarg;
				break;

			case HCX_PCAPNGNAME:
				pcapngoutname = optarg;
				break;

			case HCX_SET_SCANLIST_FROM_USER_FREQ:
				userfrequencylistname = optarg;
				break;

			case HCX_SET_SCANLIST_FROM_USER_CH:
				userchannellistname = optarg;
				break;

			case HCX_ESSIDLIST:
				essidlistname = optarg;
				break;

			case HCX_DISABLE_BEACON:
				timerwaitnd = -1;
				break;

			case HCX_DISABLE_DEAUTHENTICATION:
				deauthenticationflag = false;
				break;

			case HCX_DISABLE_PROBEREQUEST:
				proberequestflag = false;
				break;

			case HCX_DISABLE_ASSOCIATION:
				associationflag = false;
				break;

			case HCX_DISABLE_REASSOCIATION:
				reassociationflag = false;
				break;

			case HCX_BEACONTX_MAX:
				beacontxmax = strtoul(optarg, NULL, 10);
				if ((beacontxmax == 0) || (beacontxmax > (APRGLIST_MAX - 1)))
				{
					fprintf(stderr, "must be greater than > 0 and < than %d \n", APRGLIST_MAX - 1);
					exit(EXIT_FAILURE);
				}
				break;

			case HCX_PROBERESPONSETX_MAX:
				proberesponsetxmax = strtoul(optarg, NULL, 10);
				if ((proberesponsetxmax == 0) || (proberesponsetxmax > (APRGLIST_MAX - 1)))
				{
					fprintf(stderr, "must be greater than > 0 and < than %d \n", APRGLIST_MAX - 1);
					exit(EXIT_FAILURE);
				}
				break;

			case HCX_ATTEMPT_CLIENT_MAX:
				attemptclientmax = strtoul(optarg, NULL, 10);
				break;

			case HCX_ATTEMPT_AP_MAX:
				if ((attemptapmax = strtoul(optarg, NULL, 10)) > 0)
					attemptapmax *= 8;
				else
				{
					deauthenticationflag = false;
					proberequestflag = false;
					associationflag = false;
					reassociationflag = false;
				}
				break;

			case HCX_HOLD_TIME:
				if ((timehold = strtoull(optarg, NULL, 10)) < 2)
				{
					fprintf(stderr, "hold time must be > 2 seconds");
					exit(EXIT_FAILURE);
				}
				timehold *= 1000000000ULL;
				break;

			case HCX_TOT:
				if ((tottime = strtoul(optarg, NULL, 10)) < 1)
				{
					fprintf(stderr, "time out timer must be > 0 minutes\n");
					exit(EXIT_FAILURE);
				}
				tottime *= 60;
				break;

			case HCX_WATCHDOG_MAX:
				if ((watchdogcountmax = strtoul(optarg, NULL, 10)) < 1)
				{
					fprintf(stderr, "time out timer must be > 0\n");
					exit(EXIT_FAILURE);
				}
				break;

			case HCX_ERROR_MAX:
				if ((errorcountmax = strtoul(optarg, NULL, 10)) < 1)
				{
					fprintf(stderr, "error counter must be > 0\n");
					exit(EXIT_FAILURE);
				}
				break;

			case HCX_EXIT_ON_EAPOL:
				exiteapolflag = (atoi(optarg) & 0x0f) << 4;
				exiteapolpmkidflag |= exiteapolflag & EXIT_ON_EAPOL_PMKID;
				exiteapolm2flag |= exiteapolflag & EXIT_ON_EAPOL_M2;
				exiteapolm3flag |= exiteapolflag & EXIT_ON_EAPOL_M3;
				break;


			case HCX_SHOW_INTERFACE_LIST:
				if (interfacelistshortflag == true)
				{
					fprintf(stderr, "combination of options -L and -l is not allowed\n");
					exit(EXIT_FAILURE);
				}
				interfacelistflag = true;
				break;

			case HCX_SHOW_INTERFACE_LIST_SHORT:
				if (interfacelistflag == true)
				{
					fprintf(stderr, "combination of options -L and -l is not allowed\n");
					exit(EXIT_FAILURE);
				}
				interfacelistshortflag = true;
				break;

			case HCX_RD_SORT:
				rdsort = strtol(optarg, NULL, 10);
				break;

			case HCX_SET_MONITORMODE_PASSIVE:
				activemonitorflag = false;
				break;

			case HCX_HELP:
				usage(basename(argv[0]));
				break;

			case HCX_VERSION:
				version(basename(argv[0]));
				break;

			case '?':
				usageerror(basename(argv[0]));
				break;

			default:
				usageerror(basename(argv[0]));
		}
	}

	setbuf(stdout, NULL);
	hcxpid = getpid();

	if (interfacelistshortflag == false)
	{
		fprintf(stdout, "\nRequesting physical interface capabilities. This may take some time.\n"
						"Please be patient...\n\n");
	}
	if (set_signal_handler() == false)
	{
		errorcount++;
		fprintf(stderr, "failed to initialize signal handler\n");
		goto byebye;
	}
	if (init_lists() == false)
	{
		errorcount++;
		fprintf(stderr, "failed to initialize lists\n");
		goto byebye;
	}
	init_values();

	/*---------------------------------------------------------------------------*/
	if (open_control_sockets() == false)
	{
		errorcount++;
		fprintf(stderr, "failed to open control sockets\n");
		goto byebye;
	}
	if (get_interfacelist() == false)
	{
		errorcount++;
		fprintf(stderr, "failed to get interface list\n");
		goto byebye;
	}
	if (interfacelistflag == true)
	{
		show_interfacelist();
		goto byebye;
	}
	if (interfacelistshortflag == true)
	{
		show_interfacelist_short();
		goto byebye;
	}
	/*---------------------------------------------------------------------------*/
	if (getuid() != 0)
	{
		errorcount++;
		fprintf(stderr, "%s must be run as root\n", basename(argv[0]));
		goto byebye;
	}
	// ARM INTERFACE / SET CHANNEL AND SO ON
	// interfacefrequencyflag 1: Use Interface freqs in scanlist 0: Do not use interface frequency in scanlist
	// userfrequencylistname STR: Comma delim. list of freqs (2412,2417,5180,...)
	// userchannellistname STR: (1a,2a,36b...) default: 1a,6a,11a | important notice: channel numbers are not unique -- it is mandatory to add band information to the channel number (e.g. 12a)
	if (set_interface(interfacefrequencyflag, userfrequencylistname, userchannellistname) == false)
	{
		errorcount++;
		fprintf(stderr, "failed to arm interface\n");
		goto byebye;
	}
	if (essidlistname != NULL)
		read_essidlist(essidlistname);
	if (open_pcapng(pcapngoutname) == false)
	{
		errorcount++;
		fprintf(stderr, "failed to open dump file\n");
		goto byebye;
	}
	if (open_socket_rx(bpfname) == false)
	{
		errorcount++;
		fprintf(stderr, "failed to open raw packet socket\n");
		goto byebye;
	}
	if (open_socket_tx() == false)
	{
		errorcount++;
		fprintf(stderr, "failed to open transmit socket\n");
		goto byebye;
	}
	if (set_timer() == false)
	{
		errorcount++;
		fprintf(stderr, "failed to initialize timer\n");
		goto byebye;
	}
	else
	{
		if (set_timer_rca() == false)
		{
			errorcount++;
			fprintf(stderr, "failed to initialize timer\n");
			goto byebye;
		}
	}
	/*---------------------------------------------------------------------------*/
	tspecifo.tv_sec = 5;
	tspecifo.tv_nsec = 0;
	fprintf(stdout, "\nThis is a highly experimental penetration testing tool!\n"
					"It is made to detect vulnerabilities in your NETWORK mercilessly!\n\n");
	if (bpf.len == 0)
		fprintf(stderr, "BPF is unset! Make sure hcxdumptool is running in a 100%% controlled environment!\n\n");
	fprintf(stdout, "Initialize main scan loop...\033[?25l");
	nanosleep(&tspecifo, &tspeciforem);
	
	if (nl_scanloop() == false)
	{
		errorcount++;
		fprintf(stderr, "failed to initialize main scan loop\n");
	}


/*---------------------------------------------------------------------------*/
byebye:
	close_fds();
	close_sockets();
	close_lists();
	if (interfacelistshortflag == true)
		return EXIT_SUCCESS;
	fprintf(stdout, "\n\033[?25h");
	if (errorcount > 0)
		fprintf(stderr, "%" PRIu64 " ERROR(s) during runtime\n", errorcount);
#ifdef STATUSOUT
	if (totalcapturedcount > 0)
		fprintf(stdout, "%ld packet(s) captured\n", totalcapturedcount);
	if (wshbcount > 0)
		fprintf(stdout, "%ld SHB written to pcapng dumpfile\n", wshbcount);
	if (widbcount > 0)
		fprintf(stdout, "%ld IDB written to pcapng dumpfile\n", widbcount);
	if (wecbcount > 0)
		fprintf(stdout, "%ld ECB written to pcapng dumpfile\n", wecbcount);
	if (wepbcount > 0)
		fprintf(stdout, "%ld EPB written to pcapng dumpfile\n", wepbcount);
#endif
	fprintf(stdout, "\n");
	if (exiteapolflag != 0)
	{
		if ((wanteventflag & EXIT_ON_EAPOL_PMKID) == EXIT_ON_EAPOL_PMKID)
			fprintf(stdout, "exit on PMKID\n");
		if ((wanteventflag & EXIT_ON_EAPOL_M2) == EXIT_ON_EAPOL_M2)
			fprintf(stdout, "exit on EAPOL M1M2\n");
		if ((wanteventflag & EXIT_ON_EAPOL_M3) == EXIT_ON_EAPOL_M3)
			fprintf(stdout, "exit on EAPOL M1M2M3\n");
	}
	if ((wanteventflag & EXIT_ON_SIGTERM) == EXIT_ON_SIGTERM)
	{
		fprintf(stdout, "exit on sigterm\n");
	}
	else if ((wanteventflag & EXIT_ON_TOT) == EXIT_ON_TOT)
	{
		fprintf(stdout, "exit on TOT\n");
	}
	else if ((wanteventflag & EXIT_ON_WATCHDOG) == EXIT_ON_WATCHDOG)
	{
		fprintf(stdout, "exit on watchdog\n");
	}
	else if ((wanteventflag & EXIT_ON_ERROR) == EXIT_ON_ERROR)
	{
		fprintf(stdout, "exit on error\n");
	}
	fprintf(stdout, "bye-bye\n\n");
	return EXIT_SUCCESS;
}