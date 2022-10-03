// DNS Resolver.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#pragma comment(lib, "ws2_32.lib")

using namespace std;

/* DNS query types */
#define DNS_A 1 /* name -> IP */
#define DNS_NS 2 /* name server */
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name */
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */ 

/* query classes */
#define DNS_INET 1

#define MAX_DNS_LEN 512

/* flags */
#define DNS_QUERY (0 << 15) /* 0 = query; 1 = response */
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11) /* opcode - 4 bits */
#define DNS_AA (1 << 10) /* authoritative answer */
#define DNS_TC (1 << 9) /* truncated */
#define DNS_RD (1 << 8) /* recursion desired */
#define DNS_RA (1 << 7) /* recursion available */

#pragma pack(push,1) 
class QueryHeader{
public:
    USHORT type;
    USHORT c;
};
class FixedDNSheader {
public:
    USHORT ID;
    USHORT flags;
    USHORT questions;
    USHORT auth;
    USHORT answers;
    USHORT additional;
};
class DNSanswerHdr {
public:
    u_short type;
    u_short c;
    u_int ttl;
    u_short len;
};
#pragma pack(pop)

void makeDNSQuestion(char* buf, char* host)
{
    int buf_position = 0;
    
    char* start = host;
    char* temp = strchr(host, '.');
    char length = temp - start;
    while (temp != NULL) {
        length = temp - start;
        buf[buf_position++] = length;
        memcpy(buf + buf_position, start, length);
        buf_position += length;
        start = temp + 1;
        temp = strchr(temp + length, '.');
    }
    length = strlen(start);
    buf[buf_position++] = length;
    memcpy(buf + buf_position, start, length);
    buf_position += length;
    buf[buf_position] = 0;
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        printf("Please pass only URL in format -> scheme://host[:port][/path][?query][#fragment]\n");
        printf("OR\n");
    }

    WSADATA wsaData;

    //Initialize WinSock; once per program run 
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        printf("WSAStartup failed with %d\n", WSAGetLastError());
        WSACleanup();
        return 0;
    }

    char* lookup_host = argv[1];
    char* dns_server_ip = argv[2];

    printf("%s\n", lookup_host);
    printf("%s\n", dns_server_ip);

    int pkt_size = strlen(lookup_host) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
    char* buf = new char[pkt_size];

    FixedDNSheader* fdh = (FixedDNSheader*)buf;
    QueryHeader* qh = (QueryHeader*)(buf + pkt_size - sizeof(QueryHeader));

    fdh->ID = htons(1);
    fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    fdh->questions = htons(1);
    fdh->auth = htons(0);
    fdh->answers = htons(0);
    fdh->additional = htons(0);

    DWORD IP = inet_addr(lookup_host);
    qh->type=htons(DNS_PTR);
    if (IP == INADDR_NONE)
    {
        qh->type = htons(DNS_A);
    }
    else {
    }
    qh->c = htons(DNS_INET);

    int length = strlen(lookup_host) + 1;
    char* original_link = new char[length];
    strcpy_s(original_link, length, lookup_host);

    makeDNSQuestion((char*)fdh + 1, original_link);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET)
    {
        printf("socket() generated error %d\n", WSAGetLastError());
        return 0;
    }
 
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR)
    {
         printf("bind() generated error %d\n", WSAGetLastError());
         return 0;
    }

    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.S_un.S_addr = inet_addr(dns_server_ip); // server’s IP
    remote.sin_port = htons(53); // DNS port on server
    if (sendto(sock, buf, pkt_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR)
    {
        printf("send to() generated error %d\n", WSAGetLastError());
        return 0;
    }
}
