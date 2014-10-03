BITS 32

%define FRAG_LEN 0xCC
jmp call_back

body:
pop edx
mov ecx,FRAG_LEN

pop ; get ITERATION
pop ebx ; get key

decode:
mov TARGET, [edx+(ecx-1)*4] ; where target is in the buffer
xor TARGET,KEY
loop decode
; modify key for next time
; push key
; push iteration
jmp the_awesome+FRAG_LEN*ITERATION

call_back:
call body

the_awesome:
nop

; or this could copy into buffer and then recall init...
