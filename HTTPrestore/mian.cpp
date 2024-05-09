//#define HAVE_REMOTE
//#define WPCAP
#define WIN32

#include "pcap.h" 
#include <winsock2.h>
#include <string.h>
#include <stdio.h>

using namespace std;
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t* d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	//获取本地机器设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Erro in pcap_find_alldevs_ex : %s \n", errbuf);
		exit(1);
	}

	//打印列表
	for (d = alldevs; d != NULL; d = d->next) {
		printf("%d %s", ++i, d->name);
		if (d->description)
			printf("(%s) \n", d->description);
		else
			printf("(No description available)\n");
	}

	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return 0;
	}

	pcap_freealldevs(alldevs);

	return 0;
}