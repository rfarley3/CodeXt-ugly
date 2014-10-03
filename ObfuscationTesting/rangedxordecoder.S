BITS 32

jmp short callit ; jmp to the call by offset

xor_decode:
pop esi       ; get address that call stored, so esi = encrypted_area
mov edx, esi  ; put esi into edx to use for the call later
add esi, 0x12 ; adjust esi by new start offset for knowing where to start reading the data
mov edi, esi  ; put esi into edi to use for writing the data later
; cld ?
mov ecx, 0x29 ; put length to decode into ecx (hw.rawshell is 52/0x34)
mov ebx, 0xff ; put the xor key into ebx, try 0x41 for real, 0xff to use unencoded shell
xor eax, eax  ; zero the reg where the decoded value will be stored
push eax      ; zero the top of the stack

loop_decode:
lodsb         ; load byte value where esi is pointing into eax
xor eax, ebx  ; eax ^ ebx (decode eax value using ebx as key)
stosb         ; store eax (result) where edi is pointing
; don't I have to inc esi/edi? no, those insns auto increment
; xor [esi + ecx - 1 ], ebx ; what about this oneliner
loop loop_decode

call edx     ; jump to the decoded code

callit:
call xor_decode ; call pushes next insn address (encrypted area) onto stack
; encrypted_area is appended here
