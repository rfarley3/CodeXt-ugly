BITS 32


evil_code:          
	xor eax, eax
	inc eax
	xor ebx, ebx
	add bl, 7
	int 0x80
	;jmp short evil_code ; for this version only in order to skip over buf
buf:               
	db 0x55, 0x66, 0x77, 0x88
	db 0xca, 0xfe, 0xfe, 0xed 