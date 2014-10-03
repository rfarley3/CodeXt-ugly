BITS 32

call 0x4                          ; Call+4 Dword getPC
db 0xC0                           ; combines with 0xff from call 0x4 to become a FFC0 or inc eax, a junk insn
pop edi                           ; edi = addr of 0xC0
add edi, 0x?                      ; set initial target dest, ? = addr of target dest - addr of 0xC0 = length of byte of decoder starting from 0xC0
mov ebx, 0x0                      ; init the blocks counter
push ebx
push edi                          ; store so all loops can use the same target dest
per_block:                        ; the encoder must handle breaking into even chunks, filling with nops, and pre/appending necessary code
   pop edi                        ; load the target dest
   pop ebx                        ; restore the block counter
   mov ecx, 0x?                   ; set the loop counter, ? = bytes per block, ie bytes to decode per loop.
   mov esi, edi+(ebx*ecx)         ; set the target src to the correct offset (ebx'th block * bytes per block)
   xor_decode:
      lodsb                       ; eax = [esi]; esi++
      xor eax, 0xFF               ; decode target with 1B key
      stosb                       ; [edi] = eax; edi++
   loop xor_decode                ; if (ecx > 0) { jmp xor_decode; ecx--; }
   push ebx                       ; store the blocks counter for next loop
   sub edi, 0x?                   ; restore edi to original value, ? = bytes per block
   push edi
   call edi                       ; note this loop clobbers: eax, ebx, ecx, edi, esi
   compare ebx, 0x?               ; ? = blocks to decode - 1, if we've yet to reach the number of blocks to decode - 1, then do the next block
jne per_block


encoder algorithm:
Input the .S
Compile to get total bytes, divide by requested blocks to get goal bytes per block
Disassemble to insns that can used in partial .S
Do chunks of the .S from beginning until each is < goal bytes per block

Or have the user break into blocks, determine the longest one and use that as bytes per block
Prepend all but 1st with pop eax, ebx, ecx, edi, esi
Append all with push esi, edi, ecx, ebx, eax
Redefine bytes per block as the max found, pad all others to match
Modify decoder stub with # blocks, and bytes per block


Helloworld.S:
jmp short 0x15 ; getPC setup
pop ecx        ; ecx = 0x1A’s addr
xor eax,eax
mov al,0x4     ; eax = 4 = write syscall
xor ebx,ebx
inc ebx        ; target is stdout
xor edx,edx
mov dl,0xf     ; number of bytes to write
int 0x80       ; do write
mov al,0x1     ; eax = 1 = exit syscall
dec ebx        ; sets exit code 0
int 0x80       ; do exit
call dword 0x2 ; jmp 0x2 push 0x1A’s address
<string to print>