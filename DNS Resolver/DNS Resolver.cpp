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

#define DNS_OK 0 /* success */
#define DNS_FORMAT 1 /* format error (unable to interpret) */
#define DNS_SERVERFAIL 2 /* can’t find authority nameserver */
#define DNS_ERROR 3 /* no DNS entry */
#define DNS_NOTIMPL 4 /* not implemented */
#define DNS_REFUSED 5 /* server refused the query */

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
    u_short ttl;
    u_short ttl2;
    u_short len;
};
#pragma pack(pop)

SOCKET sock;
char* req_buf;

void cleanup()
{
    WSACleanup();
    closesocket(sock);
    delete[] req_buf;
}

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

void read_questions(char* buf, int& curr_pos, int nQuestions, int bytes_received) {

    for (int i = 0; i < nQuestions; i++)
    {
        if (curr_pos >= bytes_received) {
            printf("++ invalid section: not enough records");
            cleanup();
            exit(0);
        }
        unsigned char length = buf[curr_pos];
        string output_host;
        while (length != 0) {
            curr_pos++;
            char* temp = new char[length + 1];
            memcpy(temp, buf + curr_pos, length);
            temp[length] = '\0';
            
            output_host += temp;
            delete[] temp;

            curr_pos += length;

            if (curr_pos >= bytes_received) {
                printf("++ invalid section: question malformed");
                cleanup();
                exit(0);
            }

            length = buf[curr_pos];

            if (length != 0) output_host += '.';
        }
        curr_pos++;

        QueryHeader* qh = (QueryHeader*)(buf + curr_pos);
        printf("  \t%s type %d class %d\n", output_host.c_str(), htons(qh->type), htons(qh->c));
        curr_pos += 4; // skip query header
    }
}

int jump(char* res_buf, int curr_pos, string& output, int bytes_received, int& count) {

    if ((count > (bytes_received - sizeof(FixedDNSheader)) / 2))
    {
        printf("\n\t++ invalid record: jump loop");
        cleanup();
        exit(0);
    }
    if (curr_pos >= bytes_received) {
        printf("++ invalid section: not enough records");
        cleanup();
        exit(0);
    }

    unsigned char current_value = (unsigned char)res_buf[curr_pos];

    if (current_value == 0)
    {
        return curr_pos + 1;
    }
    else if (current_value >= 0xC0)
    {
        if (curr_pos + 1 >= bytes_received) {
            printf("++ invalid record: truncated jump offset");
            cleanup();
            exit(0);
        }
        int off = ((((unsigned char)res_buf[curr_pos]) & 0x3F) << 8) + (unsigned char)res_buf[curr_pos + 1];

        if (off < sizeof(FixedDNSheader))
        {
            printf("++ invalid record: jump into fixed DNS header");
            cleanup();
            exit(0);
        }

        if (off >= bytes_received) {
            printf("++ invalid record: jump beyond packet boundary");
            cleanup();
            exit(0);
        }
        count++;
        jump(res_buf, off, output, bytes_received, count);
        return curr_pos + 2;
    }
    else {
        curr_pos++; // skip byte size

        if (((curr_pos + current_value)) > bytes_received) {
            printf("++ invalid record: truncated name");
            cleanup();
            exit(0);
        }

        char* str = new char[current_value + 1];
        memcpy(str, res_buf + curr_pos, current_value);
        str[current_value] = '\0';
        curr_pos += current_value;
        output += str;

        if ((unsigned char)res_buf[curr_pos] != 0) output += ".";

        delete[] str;
        count++;
        jump(res_buf, curr_pos, output, bytes_received, count);
    }
}

void parse_response(char* res_buf, int&curr_pos, int bytes_received) {
    printf("  \t");
    string host_output;
    int count = 0;
    curr_pos = jump(res_buf, curr_pos, host_output, bytes_received, count);
    printf("%s ", host_output.c_str());

    DNSanswerHdr* dah = (DNSanswerHdr*)(res_buf + curr_pos);
    int res_type_code = htons(dah->type);

    curr_pos += sizeof(DNSanswerHdr);

    if (curr_pos >= bytes_received) {
        printf("\n\t++ invalid record: truncated RR answer header");
        cleanup();
        exit(0);
    }

   
   if (curr_pos + htons(dah->len) > bytes_received) {
        printf("\n\t++ invalid record: RR value length stretches the answer beyond packet");
        cleanup();
        exit(0);
    }

    if (res_type_code == DNS_A) {
        printf("A ");
        int x1 = (unsigned char)res_buf[curr_pos];
        int x2 = (unsigned char)res_buf[curr_pos + 1];
        int x3 = (unsigned char)res_buf[curr_pos + 2];
        int x4 = (unsigned char)res_buf[curr_pos + 3];
        printf("%d.%d.%d.%d ", x1, x2, x3, x4);
    }
    else {
        string res_type = "CNAME";
        if (res_type_code == DNS_PTR) res_type = "PTR";
        else if (res_type_code == DNS_NS) res_type = "NS";

        printf("%s ", res_type.c_str());

        string answer_output;
        int count = 0;
        jump(res_buf, curr_pos, answer_output, bytes_received, count);
        printf("%s ", answer_output.c_str());
    }
    printf("TTL = %d \n", 256 * (int)htons(dah->ttl) + (int)htons(dah->ttl2));

    curr_pos += htons(dah->len);
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        printf("Invalid Usage: Required [Lookup hostname/IP] [DNS server IP]");
        return 0;
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

    printf("Lookup : %s\n", lookup_host);

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

    USHORT TXID = htons(1);
    printf("Query  : %s, type %d, TXID 0x%.4X\n", lookup_host, ntohs(query_type), ntohs(TXID));
    printf("Server : %s\n", dns_server_ip);
    printf("***************************************\n");

    int pkt_size = strlen(lookup_host) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
    req_buf = new char[pkt_size];
    
    FixedDNSheader* fdh = (FixedDNSheader*)req_buf;
    QueryHeader* qh = (QueryHeader*)(req_buf + pkt_size - sizeof(QueryHeader));

    fdh->ID = TXID;
    fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    fdh->questions = htons(1);
    fdh->auth = htons(0);
    fdh->answers = htons(0);
    fdh->additional = htons(0);

    qh->type = query_type;
    qh->c = htons(DNS_INET);

    int length = strlen(lookup_host) + 1;
    char* original_link = new char[length];
    strcpy_s(original_link, length, lookup_host);

    makeDNSQuestion((char*)(fdh + 1), original_link);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
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

    int current_attempt = 0;
    clock_t start_t, end_t;
    while (current_attempt < MAX_ATTEMPTS)
    {
        start_t = clock();
        printf("Attempt %d with %d bytes...", current_attempt, pkt_size);
        current_attempt++;
        if (sendto(sock, req_buf, pkt_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR)
        {
            printf("socket generated error %d\n", WSAGetLastError());
            cleanup();;
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

        end_t = clock();
        if (available == 0) {
            printf("timeout in %d ms\n", end_t-start_t);
            delete[] res_buf;
            continue;
        }

        if (available == SOCKET_ERROR)
        {
            printf("socket generated error %d\n", WSAGetLastError());
            cleanup();
            delete[] res_buf;
            return 0;
        };

        if (available > 0)
        {
            int bytes_received = recvfrom(sock, res_buf, MAX_DNS_LEN, 0, (struct sockaddr*) &res_server, &res_server_size);

            if (res_server.sin_addr.S_un.S_addr != remote.sin_addr.S_un.S_addr || res_server.sin_port != remote.sin_port) {
                printf("++ invalid reply: wrong server replied\n");
                cleanup();
                delete[] res_buf;
                return 0;
            }

            if (bytes_received == SOCKET_ERROR)
            {
                printf("socket error %d\n", WSAGetLastError());
                cleanup();
                delete[] res_buf;
                return 0;
            };

            //printf("bytes_received %d\n", bytes_received);

            if (bytes_received < sizeof(FixedDNSheader)) {
                printf("\n  ++  invalid reply: packet smaller than fixed DNS header");
                cleanup();
                delete[] res_buf;
                return 0;
            }
            end_t = clock();
            printf(" response in %d ms with %d bytes\n", (end_t-start_t), bytes_received);
            FixedDNSheader* res_fdh = (FixedDNSheader*)res_buf;

            printf("  TXID 0x%.4X flags 0x%.4X questions %d answers %d authority %d additional %d\n",
                htons(res_fdh->ID), htons(res_fdh->flags), htons(res_fdh->questions), htons(res_fdh->answers), htons(res_fdh->auth), htons(res_fdh->additional));
            
            if (fdh->ID != res_fdh->ID)
            {
                printf("  ++ invalid reply: TXID mismatch, sent 0x%.4X, received 0x%.4X", htons(fdh->ID), htons(res_fdh->ID));
                cleanup();
                return 0;
            }


            int rcode = htons(res_fdh->flags) & 0x000f;

            if (rcode == 0) printf("  succeeded with Rcode = %d\n", rcode);
            else {
                printf("  failed with Rcode = %d\n", rcode);
                cleanup();
                return 0;
            }

            int curr_pos = sizeof(FixedDNSheader);
            printf("  ------------ [questions] ------------\n");
            read_questions(res_buf, curr_pos, htons(res_fdh->questions), bytes_received);

            if (htons(res_fdh->answers) > 0)
            {
                printf("  ------------ [answers] ------------------\n");
                for (int i = 0; i < htons(res_fdh->answers); i++) {
                    parse_response(res_buf, curr_pos, bytes_received);
                }
            }

            if (htons(res_fdh->auth) > 0)
            {
                printf("  ------------ [authority] ------------------\n");
                for (int i = 0; i < htons(res_fdh->auth); i++) {
                    parse_response(res_buf, curr_pos, bytes_received);
                }
            }

            if (htons(res_fdh->additional) > 0)
            {
                printf("  ------------ [additional] ------------------\n");
                for (int i = 0; i < htons(res_fdh->additional); i++) {
                    parse_response(res_buf, curr_pos, bytes_received);
                }
            }
            cleanup();
            delete[] res_buf;
            break;
        }
    }

}

//C:\Users\yatingupta\source\repos\YatinGupta777\DNS-Resolver\x64\Debug