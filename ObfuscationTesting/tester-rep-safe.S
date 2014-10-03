; self-overwrite REP tester
BITS 32


jmp short callit ; jmp to the call by offset

body:
   pop edx                  ; get address that call stored on stack (store for future ref)
   ; so now esi equals an address at a known relationship to what we want to address
   mov edi, edx             ; set string dest
;   add edi, 0xd8            ; we want edi to point to the last NOP, adjust for that relative value
   sub edi, 40              ; addr of HW string - addr of final NOP
   std                      ; sets reverse string flag (do actions from end)
   xor ebx, ebx             ; zero out our test variable
   mov al, 0x43             ; set eax to the opcode inc ebx
   ;mov ecx, 0x06            ; set rep count to 6 overwrites rep stosb
   mov ecx, 0x04            ; set rep count to 4 only overwrites the nops
   rep stosb                ; from EDI backwards, write AL ecx times
   NOP
   NOP
   NOP
   NOP                      ; edi-X = addr of this byte; 0x42 - 40(0xd8) = 0x1a
   cld                      ; clean up and clear/reset string flag to normal

printf:
   add ebx, 0x30            ; convert ebx from unsigned int to char
   mov byte [edx+0x15], bl  ; put value into output string
   xor eax, eax             ; zero out eax
   mov al, 0x04             ; set eax to 4: syscall number for write(int fd,char *str, int len)
   xor ebx, ebx             ; zero out ebx
   mov bl, 0x01             ; set ebx to fd of STDOUT
   ;xor ecx, ecx             ; zero out ecx
   mov ecx, edx             ; set ecx to the address of the string to print
   xor edx, edx             ; zero out edx
   mov dl, 0x17             ; set edx to the length of the string to print
   int 0x80

exit:
   xor eax, eax             ; zero out eax
   mov al, 0x01             ; set eax to 1: syscall number for exit
   xor ebx, ebx             ; set set ebx to 0, the return value
   int 0x80

callit:
   call body                ; call pushes next insn address onto stack

section .data
   message: db "Hello, World! ebx: u", 0x0a

