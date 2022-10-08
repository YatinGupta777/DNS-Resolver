// DNS Resolver.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#pragma comment(lib, "ws2_32.lib")

using namespace std;

/* constants */
#define MAX_DNS_LEN 512
#define MAX_ATTEMPTS 3

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
    USHORT answers;
    USHORT auth;
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

    DWORD IP = inet_addr(lookup_host);
    USHORT query_type = htons(DNS_PTR);

    if (IP == INADDR_NONE)
    {
        query_type = htons(DNS_A);
    }
    else {
        //reverse IP
        struct in_addr ia;
        ia.S_un.S_addr = htonl(IP);
        char* t = inet_ntoa(ia);
        const char* t2 = ".in-addr.arpa";

        char* str3 = (char*)malloc(1 + strlen(t) + strlen(t2));
        strcpy(str3, t);
        strcat(str3, t2);
        lookup_host = str3;
    }

    int pkt_size = strlen(lookup_host) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
    char* req_buf = new char[pkt_size];
    
    FixedDNSheader* fdh = (FixedDNSheader*)req_buf;
    QueryHeader* qh = (QueryHeader*)(req_buf + pkt_size - sizeof(QueryHeader));

    fdh->ID = htons(1);
    fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    fdh->questions = htons(1);
    fdh->auth = htons(0);
    fdh->answers = htons(0);
    fdh->additional = htons(0);

    qh->type = query_type;
    qh->c = htons(DNS_INET);

    printf("%d\n", sizeof(fdh));

    int length = strlen(lookup_host) + 1;
    char* original_link = new char[length];
    strcpy_s(original_link, length, lookup_host);

    makeDNSQuestion((char*)(fdh + 1), original_link);

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
    remote.sin_port = htons(53); // DNS port on serve

    int count = 0;
    while (count++ < MAX_ATTEMPTS)
    {
        printf("Attempt %d with %d bytes...", count, sizeof(req_buf));
        if (sendto(sock, req_buf, pkt_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR)
        {
            printf("send to() generated error %d\n", WSAGetLastError());
            return 0;
        };
        // get ready to receive
        
        fd_set fd;
        FD_ZERO(&fd); // clear the set
        FD_SET(sock, &fd); // add your socket to the set
        timeval tp;
        tp.tv_sec = 10;
        tp.tv_usec = 0;

        struct sockaddr_in res_server;
        int res_server_size = sizeof(res_server);
        char* res_buf = new char[MAX_DNS_LEN];
        int available = select(0, &fd, NULL, NULL, &tp);

        if (available == 0) {
            printf("timeout\n");
            return 0;
        }

        if (available == SOCKET_ERROR)
        {
            printf("select error %d\n", WSAGetLastError());
            return 0;
        };

        if (available > 0)
        {
            int bytes_received = recvfrom(sock, res_buf, MAX_DNS_LEN, 0, (struct sockaddr*) &res_server, &res_server_size);

            if (res_server.sin_addr.S_un.S_addr != remote.sin_addr.S_un.S_addr || res_server.sin_port != remote.sin_port) {
                printf("COMPLAIN\n");
                return 0;
            }

            if (bytes_received == SOCKET_ERROR)
            {
                printf("bytes_received to() generated error %d\n", WSAGetLastError());
                return 0;
            };
            
           // int off = ( (ans[curPos] & 0x3F) << 8) + ans[curPos + 1];
            printf("response in with %d bytes\n", sizeof(res_buf));
            FixedDNSheader* res_fdh = (FixedDNSheader*)res_buf;

            printf("TXID %d flags %d questions %d answers %d authority %d additional %d\n",
                htons(res_fdh->ID), htons(res_fdh->flags), htons(res_fdh->questions), htons(res_fdh->answers), htons(res_fdh->auth), htons(res_fdh->additional));

            break;
        }
        // error checking here
    }

}
