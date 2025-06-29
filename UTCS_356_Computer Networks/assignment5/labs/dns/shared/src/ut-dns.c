#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "lib/tdns/tdns-c.h"

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

    /* PART1 TODO: Implement a DNS nameserver for the utexas.edu zone */
    
    /* 1. Create an **UDP** socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);


    /* 2. Initialize server address (INADDR_ANY, DNS_PORT) */
    /* Then bind the socket to it */
    memset(&server_addr, 0, sizeof server_addr);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);

    bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));


    /* 3. Initialize a server context using TDNSInit() */
    /* This context will be used for future TDNS library function calls */
    struct TDNSServerContext *context = TDNSInit();

    /* 4. Create the utexas.edu zone using TDNSCreateZone() */
    /* Add an IP address for www.utexas.edu domain using TDNSAddRecord() */
    /* Add the UTCS nameserver ns.cs.utexas.edu using using TDNSAddRecord() */
    /* Add an IP address for ns.cs.utexas.edu domain using TDNSAddRecord() */
    TDNSCreateZone(context, "utexas.edu");
    TDNSAddRecord(context, "utexas.edu", "www", "40.0.0.10", NULL);
    TDNSAddRecord(context, "utexas.edu", "cs", NULL, "ns.cs.utexas.edu");
    TDNSAddRecord(context, "cs.utexas.edu", "ns", "50.0.0.30", NULL);

    /* 5. Receive a message continuously and parse it using TDNSParseMsg() */
    while (1) {
        ssize_t recvlength = recvfrom(sockfd, buffer, BUFFER_SIZE, 0 , (struct sockaddr *)&client_addr, &client_len);



        struct TDNSParseResult parsed;
        memset(&parsed, 0 , sizeof(parsed));


        
        if (TDNSParseMsg(buffer, recvlength, &parsed) != TDNS_QUERY) {
            continue;
        }

        if ((parsed.qtype == A || parsed.qtype == AAAA || parsed.qtype == NS) && parsed.qname != NULL){
            struct TDNSFindResult result;
            memset(&result, 0, sizeof(result));
            uint8_t found = TDNSFind(context, &parsed, &result);
            sendto(sockfd, result.serialized, result.len, 0, (struct sockaddr *)&client_addr, client_len);
        }
    }
    close(sockfd);



    /* 6. If it is a query for A, AAAA, NS DNS record */
    /* find the corresponding record using TDNSFind() and send the response back */
    /* Otherwise, just ignore it. */

    return 0;
}

