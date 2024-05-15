//#define HAVE_REMOTE
//#define WPCAP

#define WIN32

#include "pcap.h" 
#include <winsock2.h>
#include <string.h>
#include <stdio.h>

#include <ctype.h>
#include <time.h>

using namespace std;
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

//#include "pheader.h"

//#define HAVE_REMOTE

//typedef unsigned char u_char;
//typedef unsigned int u_int;
//typedef unsigned short  u_short;


struct ether_header {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

struct ip_header {
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    struct ip_address  saddr;
    struct ip_address  daddr;
    u_int   op_pad;
};

struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
};

struct tcp_header {
    u_short th_sport;
    u_short th_dport;
    u_int th_seq;
    u_int th_ack;
    u_short th_len_resv_code;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
    u_int   op_pad;
};

struct http_session {
    char header[4096];
    char body[4096];
};

void parse_http(char* http_txt, struct http_session* session) 
{
    // 找到头部和正文的分隔符"\r\n\r\n"
    char* separator = strstr(http_txt, "\r\n\r\n");
    if (separator) {
        // 复制头部信息到session->header
        strncpy(session->header, http_txt, separator - http_txt);
        session->header[separator - http_txt] = '\0';

        // 复制正文信息到session->body
        strcpy(session->body, separator + 4);
    }
    else {
        // 如果没有找到分隔符，那么整个http_txt就是头部
        strcpy(session->header, http_txt);
        session->body[0] = '\0';
    }
}

void print_http(struct http_session* session) 
{
    printf("Header: \n%s\n", session->header);

    // 检查Content-Type
    char* content_type = strstr(session->header, "Content-Type: ");
    if (content_type) {
        content_type += strlen("Content-Type: ");
        char* end = strchr(content_type, '\r');
        if (end) {
            *end = '\0';
        }

        // 如果Content-Type是文本类型，直接打印body
        if (strncmp(content_type, "text/html", strlen("text/html")) == 0 ||
            strncmp(content_type, "text/css", strlen("text/css")) == 0 ||
            strncmp(content_type, "application/json", strlen("application/json")) == 0 ||
            strncmp(content_type, "application/xml", strlen("application/xml")) == 0) {
            printf("Body: \n%s\n", session->body);
        }
        else {
            // 如果Content-Type是二进制类型，打印二进制数据
            printf("Body: \n");
            for (int i = 0; session->body[i] != '\0'; ++i) {
                printf("%02x ", (unsigned char)session->body[i]);
            }
            printf("\n");
        }

        if (end) {
            *end = '\r';
        }
    }
    else {
        printf("Body: \n%s\n", session->body);
    }
}

int is_readable(char c) {
    unsigned char uc = (unsigned char)c;
    if (uc > 255) {
        printf("Error: Invalid character value %d\n", c);
        return 0;
    }
    return isalnum(uc) || ispunct(uc) || isspace(uc) || isprint(uc);
}

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuff) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i) {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    if ((adhandle = pcap_open(
        d->name, 
        65536,
        PCAP_OPENFLAG_PROMISCUOUS,
        1000, 
        NULL, 
        errbuf
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("\nlistening on %s...\n", d->description);

    pcap_freealldevs(alldevs);

    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int rst = 0;
    while ((rst = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
        if (rst == 0) {
            continue;
        }
        struct ether_header* eh = (struct ether_header*)pkt_data;

        if (ntohs(eh->ether_type) == 0x0800) {
            struct ip_header* ih = (struct ip_header*)(pkt_data + 14);
            
            if (ntohs(ih->proto) == 0x0600) {
                int ip_len = ntohs(ih->tlen);
                int find_http = 0;
                char http_txt[1500] = "";
                char* ip_pkt_data = (char*)ih;

                for (int i = 0; i < ip_len; ++i) {
                    if (!find_http && (i + 3 < ip_len && strncmp(ip_pkt_data + i, "GET ", strlen("GET ")) == 0)
                        || (i + 4 < ip_len && strncmp(ip_pkt_data + i, "POST ", strlen("POST ")) == 0)) {
                        find_http = 1;
                    }
                    if (!find_http && i + 8 < ip_len && strncmp(ip_pkt_data + i, "HTTP/1.1 ", strlen("HTTP/1.1 ")) == 0) {
                        find_http = 1;
                    }
                    if (find_http && is_readable(ip_pkt_data[i])) {
                        strncat(http_txt, &ip_pkt_data[i], 1);
                    }
                }

                if (strcmp(http_txt, "") != 0) {
                    char timestr[16];
                    time_t local_tv_sec;
                    local_tv_sec = header->ts.tv_sec;
                    struct tm* ltime = localtime(&local_tv_sec);
                    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
                    printf("%s,%.6d len:%d\n\n", timestr, header->ts.tv_usec, header->len);

                    /*printf("%s\n", http_txt);*/
                    struct http_session session;
                    parse_http(http_txt, &session);
                    print_http(&session);
                }
            }
        }
    }
    return 0;
}




