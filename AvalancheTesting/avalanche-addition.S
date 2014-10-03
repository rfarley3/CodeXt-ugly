BITS 32

jmp short callit ; jmp to the call by offset

add_em:
pop esi       ; get address that call stored, so esi = &x
mov edi, esi  ; put esi into edi
add edi, 2    ; set edi = &z

xor eax, eax  ; zero the reg where the value will be stored
lodsb         ; load byte value where esi is pointing into eax; eax = x
mov ebx, eax  ; ebx = x
lodsb         ; eax = y
add eax, ebx  ; eax = x + y
stosb         ; store eax (result) where edi is pointing; edi = z


xor eax, eax                          
inc eax                               ; _exit 0x1
xor ebx, ebx                          
inc ebx                               ; status = 1
int 0x80                              ; _exit (status);

callit:
call add_em ; call pushes next insn address (encrypted area) onto stack
; single byte values for x, y, and z are here

db 0x1
db 0x2
db 0x0
