; salc test
BITS 32

xor eax,eax ; clear eax
mov eax, 6  ; default is sys_close (just a random syscall that won't crap out the system)
salc        ; set al to -1 on carry, else 0
int 0x80    ; should be 0 if emulated properly (as opposed to 6 if insn skipped)

; once it gets to this offset the results will be different

xor eax,eax ; clear eax
mov eax, 6  ; default is sys_close (just a random syscall that won't crap out the system)
stc         ; set carry
salc        ; set al to -1 on carry, else 0
int 0x80    ; should be -1 (0xff) if emulated properly (as opposed to 6 if insn skipped)