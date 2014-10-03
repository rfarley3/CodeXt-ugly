; test test
BITS 32

xor eax, eax         ; eax = 0
test eax, 11223344h  ; 
int 0x80             ; syscall (0), see if disasm'bles test correctly