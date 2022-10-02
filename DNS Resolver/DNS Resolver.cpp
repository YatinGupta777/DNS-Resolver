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


int main(int argc, char** argv)
{
    std::cout << "Hello World!\n";

    if (argc != 3)
    {
        printf("Please pass only URL in format -> scheme://host[:port][/path][?query][#fragment]\n");
        printf("OR\n");
    }

    string lookup_host = argv[1];
    string dns_server_ip = argv[2];

    printf("%s\n", lookup_host);
    printf("%s\n", dns_server_ip);

    int pkt_size = strlen(lookup_host.c_str()) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
    char* buf = new char[pkt_size];

    FixedDNSheader* fdh = (FixedDNSheader*)buf;
    QueryHeader* qh = (QueryHeader*)(buf + pkt_size - sizeof(QueryHeader));

    fdh->ID = htons(1);
    fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    fdh->questions = htons(1);
    fdh->auth = htons(0);
    fdh->answers = htons(0);
    fdh->additional = htons(0);

    DWORD IP = inet_addr(lookup_host.c_str());
    qh->type=htons(DNS_PTR);
    if (IP == INADDR_NONE)
    {
        qh->type = htons(DNS_A);
    }
    else {
    }
    qh->c = htons(DNS_INET);
}
