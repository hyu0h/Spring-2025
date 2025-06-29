#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "lib/tdns/tdns-c.h"

/* DNS header structure */
struct dnsheader {
        uint16_t        id;         /* query identification number */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                        /* fields in third byte */
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritative answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        rcode :4;       /* response code */
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ 
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritative answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        cd: 1;          /* checking disabled by resolver */
        unsigned        ad: 1;          /* authentic data from named */
        unsigned        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif
                        /* remaining bytes */
        uint16_t        qdcount;    /* number of question records */
        uint16_t        ancount;    /* number of answer records */
        uint16_t        nscount;    /* number of authority records */
        uint16_t        arcount;    /* number of resource records */
};

/* A few macros that might be useful */
/* Feel free to add macros you want */
#define DNS_PORT 53
#define BUFFER_SIZE 2048 

int main() {
    /* A few variable declarations that might be useful */
    /* You can add anything you want */
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    /* PART2 TODO: Implement a local iterative DNS server */
    
    /* 1. Create an **UDP** socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* 2. Initialize server address (INADDR_ANY, DNS_PORT) */
    /* Then bind the socket to it */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));

    /* 3. Initialize a server context using TDNSInit() */
    /* This context will be used for future TDNS library function calls */
    struct TDNSServerContext *context = TDNSInit();


    /* 4. Create the edu zone using TDNSCreateZone() */
    /* Add the UT nameserver ns.utexas.edu using using TDNSAddRecord() */
    /* Add an IP address for ns.utexas.edu domain using TDNSAddRecord() */
    TDNSCreateZone(context, "edu");
    TDNSAddRecord(context, "edu", "utexas", NULL, "ns.utexas.edu");
    TDNSAddRecord(context, "utexas.edu", "ns", "40.0.0.20", NULL);


    /* 5. Receive a message continuously and parse it using TDNSParseMsg() */

    /* 6. If it is a query for A, AAAA, NS DNS record, find the queried record using TDNSFind() */
    /* You can ignore the other types of queries */

        /* a. If the record is found and the record indicates delegation, */
        /* send an iterative query to the corresponding nameserver */
        /* You should store a per-query context using putAddrQID() and putNSQID() */
        /* for future response handling */

        /* b. If the record is found and the record doesn't indicate delegation, */
        /* send a response back */

        /* c. If the record is not found, send a response back */

    /* 7. If the message is an authoritative response (i.e., it contains an answer), */
    /* add the NS information to the response and send it to the original client */
    /* You can retrieve the NS and client address information for the response using */
    /* getNSbyQID() and getAddrbyQID() */
    /* You can add the NS information to the response using TDNSPutNStoMessage() */
    /* Delete a per-query context using delAddrQID() and putNSQID() */

    /* 7-1. If the message is a non-authoritative response */
    /* (i.e., it contains referral to another nameserver) */
    /* send an iterative query to the corresponding nameserver */
    /* You can extract the query from the response using TDNSGetIterQuery() */
    /* You should update a per-query context using putNSQID() */
    while (1) {
        ssize_t n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                             (struct sockaddr*)&client_addr, &client_len);

        struct TDNSParseResult parsed;
        uint8_t msg = TDNSParseMsg(buffer, n, &parsed);

        if (msg == TDNS_QUERY) {
            if (parsed.qtype == A || parsed.qtype == NS || parsed.qtype == AAAA) {
                struct TDNSFindResult result;
                uint8_t found = TDNSFind(context, &parsed, &result);

                if (found) {
                    if (parsed.nsIP) {
                        uint16_t qid = parsed.dh->id;

                        putAddrQID(context, qid, &client_addr);
                        putNSQID(context, qid, parsed.nsIP, parsed.nsDomain);

                        struct sockaddr_in ns_addr = {0};
                        ns_addr.sin_family = AF_INET;
                        ns_addr.sin_port   = htons(DNS_PORT);
                        inet_pton(AF_INET, parsed.nsIP, &ns_addr.sin_addr);
                            
                        if (sendto(sockfd, buffer, n, 0,
                                   (struct sockaddr*)&ns_addr, sizeof(ns_addr)) < 0) {
                            perror("error");
                        }
                    } else {
                        if (sendto(sockfd, result.serialized, result.len, 0,
                                   (struct sockaddr*)&client_addr, client_len) < 0) {
                            perror("error");
                        }
                    }
                } else {
                    if (sendto(sockfd, result.serialized, result.len, 0,
                               (struct sockaddr*)&client_addr, client_len) < 0) {
                        perror("error");
                    }
                }
            }
        } else {
            uint16_t qid = parsed.dh->id;
            struct sockaddr_in original_client = {0};
            getAddrbyQID(context, qid, &original_client);

            const char *stored_nsIP, *stored_nsDomain;
            getNSbyQID(context, qid, &stored_nsIP, &stored_nsDomain);

            if (parsed.dh->aa) {
                uint64_t msg_length = TDNSPutNStoMessage(buffer, n, &parsed, stored_nsIP, stored_nsDomain);
                if (sendto(sockfd, buffer, msg_length, 0,
                           (struct sockaddr*)&original_client, sizeof(original_client)) < 0) {
                    perror("error");
                }
                delAddrQID(context, qid);
                delNSQID(context, qid);
            } else {

                char iter_buf[MAX_RESPONSE];
                ssize_t qlen = TDNSGetIterQuery(&parsed, iter_buf);

                putNSQID(context, qid, parsed.nsIP, parsed.nsDomain);

                struct sockaddr_in ns_addr = {0};
                ns_addr.sin_family = AF_INET;
                ns_addr.sin_port   = htons(DNS_PORT);
                inet_pton(AF_INET, parsed.nsIP, &ns_addr.sin_addr);
                if (sendto(sockfd, iter_buf, qlen, 0,
                           (struct sockaddr*)&ns_addr, sizeof(ns_addr)) < 0) {
                    perror("error");
                }
            }
        }
    }
    close(sockfd);
    return 0;
}

