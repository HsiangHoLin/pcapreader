#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <netinet/in.h>
#include <unistd.h>

#include "linux_compat.h"

/*************************/

#define TICK_RESOLUSION 1

static pcap_t *g_pacp_handle = NULL; // rename to g_pacp_handle
static char *g_pcap_file = NULL; // rename to gg_pcap_file
static char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
static int _pcap_datalink_type = 0;

static u_int8_t shutdown_app = 0;
static u_int32_t g_pcap_pkt_num = 0;

/*************************/

static int openg_pcap_file(void)
{
	g_pacp_handle = pcap_open_offline(g_pcap_file, _pcap_error_buffer);

	if (g_pacp_handle == NULL) 
	{
		printf("ERROR: could not open pcap file: %s\n", _pcap_error_buffer);
		return -1;
    } //else printf("Reading packets from pcap file %s...\n", g_pcap_file);

	_pcap_datalink_type = pcap_datalink(g_pacp_handle);

	return 0;
}

static void closeg_pcap_file(void)
{
  if (g_pacp_handle != NULL) {
    pcap_close(g_pacp_handle);
  }
}

void sigproc(int sig) 
{
	static int called = 0;

	if(called) return; else called = 1;
	shutdown_app = 1;

	closeg_pcap_file();
	exit(0);
}


static u_int32_t last_sec = 0;
static u_int32_t last_usec = 0;
static int g_use_pcap_time = 0;
	
void handle_ip_packet(struct timeval tv, iphdr_t *iph, u_int32_t ip_len, const u_char* raw_pkt)
{
	if(last_sec)
	{
		if(g_use_pcap_time)
		{
			u_int32_t diff_sec = tv.tv_sec - last_sec;
			u_int32_t diff_usec = tv.tv_usec - last_usec;

			usleep(diff_sec * 1000000 + diff_usec);
		}
	}
	last_sec = tv.tv_sec;
	last_usec = tv.tv_usec;

    printf("[%d] ip_version= %d, ip_len= %d\n", g_pcap_pkt_num, iph->version, (iph)->ihl << 2);
    // do something to the ip packet here
    // payload starts at iph + ip_len + tcp_len or udp_len
}

static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
	ethhdr_t *ethernet = NULL;
	iphdr_t *iph = NULL;
	u_int16_t ip_offset;
	u_int16_t type;
	u_int16_t frag_off;

	g_pcap_pkt_num++;

	if(_pcap_datalink_type == DLT_EN10MB)
	{
		ethernet = (ethhdr_t*) packet;
		ip_offset = sizeof(ethhdr_t);
		type = ntohs(ethernet->h_proto);
	} 
	else if(_pcap_datalink_type == 113 /* Linux Cooked Capture */) 
	{
		type = (packet[14] << 8) + packet[15];
		ip_offset = 16;
	}
	else
	{
		return;
	}

	if(type == 0x8100 /* VLAN */)
	{
		type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
		ip_offset += 4;
	}

	iph = (iphdr_t *) (packet + ip_offset);

	if (type == ETH_P_IP && header->caplen >= ip_offset) 
	{
		frag_off = ntohs(iph->frag_off);

		if(header->caplen < header->len) printf("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
	}

	handle_ip_packet(header->ts, iph, header->len - ip_offset, packet);
}

static void runPcapLoop(void)
{
	if(!shutdown_app)
		pcap_loop(g_pacp_handle, -1, &pcap_packet_callback, NULL);
}

void run_lib() 
{
	struct timeval begin, end;
	u_int64_t tot_usec;
  
	if(openg_pcap_file() != 0) return;

	signal(SIGINT, sigproc);

	printf("======== Pcap reading start =======\n");

	gettimeofday(&begin, NULL);
	runPcapLoop();
	gettimeofday(&end, NULL);
  
	tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);

	printf("======= Pcap reading finished =====\n");
	printf("Run time = %lu usec\n", (long unsigned int)tot_usec);
	printf("Total pkt num = %u\n", g_pcap_pkt_num);

	closeg_pcap_file();
}

static void help(void) 
{
	printf("pcapreader -p <file.pcap> [-t]\n"
		"Usage:\n"
		"  -p <file.pcap>     | Specify a pcap file to read packets from\n"
		"  -t                 | Play in pcap time\n"
		);
	exit(-1);
}

static void parse_options(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "p:t")) != EOF) 
	{
		switch (opt) 
		{
		case 'p':
			g_pcap_file = optarg;
			break;
		case 't':
			g_use_pcap_time = 1;
			break;
		default:
			help();
			break;
		}
	}

	if (g_pcap_file == NULL || strcmp(g_pcap_file, "") == 0) 
    {
        help();
    }
}

int main(int argc, char* argv[])
{
	parse_options(argc, argv);

	run_lib();

	return 0;
}
