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

int main(int argc, char** argv)
{
    std::cout << "Hello World!\n";

    if (argc != 3)
    {
        printf("Please pass only URL in format -> scheme://host[:port][/path][?query][#fragment]\n");
        printf("OR\n");
    }

    char* lookup_host = argv[1];
    char* dns_server_ip = argv[2];

    printf("%s\n", lookup_host);
    printf("%s\n", dns_server_ip);

    DWORD IP = inet_addr(lookup_host);
    if (IP == INADDR_NONE)
    {
        printf("NO IP YO");
    }
}
