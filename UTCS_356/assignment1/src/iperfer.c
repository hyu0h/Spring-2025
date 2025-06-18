#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PORT_MAX (1<<16)-1 // 65535
#define BUFFER_SIZE 1000
#define MAX_CLIENT 10

/* get_time function */
/* Input: None */
/* Output: current time in seconds */
/* (double data type and ns precision) */
double
get_time(void) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec + (now.tv_nsec * 1e-9);
}

void
handle_server(int port) {
    printf("HANDLING SERVER\n");
    char buffer[BUFFER_SIZE];
 
    
    /* TODO: Implement server mode operation here */
    /* 1. Create a TCP/IP socket with `socket` system call */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    


    /* 2. `bind` socket to the given port number */
    struct sockaddr_in sin;
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port);
    
    bind(sockfd, (struct sockaddr *)&sin, sizeof(sin));


    /* 3. `listen` for TCP connections */

    listen(sockfd, MAX_CLIENT);

    int n_sock;
    int addrlen = sizeof(sin);
    /* 4. Wait for the client connection with `accept` system call */
    if ((n_sock = accept(sockfd, (struct sockaddr *)&sin, (socklen_t *)&addrlen)) < 0) {
        perror("error");
        exit(1);
    }

    /* 5. After the connection is established, received data in chunks of 1000 bytes */
    double start_time = get_time();
    double end_time;
    int len = 0;
    long long total = 0;
    while ((len = recv(n_sock, buffer, BUFFER_SIZE, 0)) > 0) {
        total += len;
    }
    

    close(n_sock);
    close(sockfd);

    end_time = get_time();

    double totalkb = (double) total / 1000;
    double elapsed = end_time - start_time;
    double rate = (totalkb * 8) / (elapsed * 1e6);

    /* 6. When the connection is closed, the program should print out the elapsed time, */
    /*    the total number of bytes received (in kilobytes), and the rate */ 
    /*    at which the program received data (in Mbps) */
    printf("Elapsed Time: %0.3f\n", elapsed);
    printf("Total bytes: %0.3f\n", totalkb);
    printf("Rate: %0.3f\n", rate);

    close(sockfd);
    return;
}

void
handle_client(const char *addr, int port, int duration) {
    printf("HANDLING CLIENT\n");
    /* TODO: Implement client mode operation here */

    
    /* 1. Create a TCP/IP socket with socket system call */
    int clientsock = socket(AF_INET, SOCK_STREAM, 0);
    /* 2. `connect` to the server specified by arguments (`addr`, `port`) */
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    inet_pton(AF_INET, addr, &server_addr.sin_addr);

    connect(clientsock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    /* 3. Send data to the connected server in chunks of 1000bytes */
    double start_time = get_time();
    double end_time = start_time;
    long long total = 0;
    int len = 0;

    while (end_time - start_time < duration) {
        len = send(clientsock, buffer, BUFFER_SIZE, 0);
        total += len;
        end_time = get_time();
    }


    /* 4. Close the connection after `duration` seconds */
    close(clientsock);
    /* 5. When the connection is closed, the program should print out the elapsed time, */
    /*    the total number of bytes sent (in kilobytes), and the rate */ 
    /*    at which the program sent data (in Mbps) */
    
    double totalkb = (double) total / 1000;
    double elapsed = end_time - start_time;
    double rate = (totalkb * 8) / (elapsed * 1e6);
    printf("Elapsed Time: %0.3f\n", elapsed);
    printf("Total bytes: %0.3f\n", totalkb);
    printf("Rate: %0.3f\n", rate);
    return;
}

int
main(int argc, char *argv[]) {
    /* argument parsing */
    int mode = 0, server_tcp_port = 0, duration = 0;
    char *server_host_ipaddr = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "csh:p:t:")) != -1) {
        switch (opt) {
            case 'c':
                mode = 1;
                break;
            case 's':
                mode = 2;
                break;
            case 'h':
                server_host_ipaddr = optarg;
                break;
            case 'p':
                server_tcp_port = atoi(optarg);
                break;
            case 't':
                duration = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s -c -h <server_host_ipaddr> -p <server_tcp_port> -t <duration_in_sec>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (mode == 0) {
        fprintf(stderr, "Please specify either -c (client mode) or -s (server mode).\n");
        exit(EXIT_FAILURE);
    }

    if (mode == 1) {
        if (server_host_ipaddr == NULL || duration == 0 || server_tcp_port == 0) {
            fprintf(stderr, "Client mode requires -h, -p, and -t options.\n");
            exit(EXIT_FAILURE);
        }

        /* TODO: Implement argument check here */
        /* 1. Check server_tcp_port is within the port number range */
        /* 2. Check the duration is a positive number */
        if (server_tcp_port < 1 || server_tcp_port > PORT_MAX || duration <= 0) {
            printf("ERROR\n");
            exit(EXIT_FAILURE);
        }



        printf("Client mode: Server IP = %s, Port = %d, Time Window = %d\n", server_host_ipaddr, server_tcp_port, duration);
        handle_client (server_host_ipaddr, server_tcp_port, duration);

    } else if (mode == 2) {
        // Server mode logic goes here
        if (server_tcp_port == 0) {
            fprintf(stderr, "Server mode requires -p option.\n");
            exit(EXIT_FAILURE);
        }

        /* TODO: Implement argument check here */
        /* Check server_tcp_port is within the port number range */
        if (server_tcp_port < 1 || server_tcp_port > PORT_MAX) {
            printf("ERROR\n");
            exit(EXIT_FAILURE);
        }
        
        printf("Server mode, Port = %d\n", server_tcp_port);
        handle_server(server_tcp_port);
    }

    return 0;
}
