BITS 32

; writes data over a stack variable in order to overwrite retaddr

; to make run legit, skip prepbuf and give it buf of 0x11223300 (4B null terminated)

main:
	;push 0x11223344    ; vuln_obj
	;push esp           ; esp now holds an addr pointing to vuln_obj of value 0x11223344 that we can overflow and overwrite retaddr
	call prepBuf       ; push &buf and jmp, getPC method
	call skipBuf
evilCode:           ; just put the asm here, and let nasm convert it into the bytes to be executed
	xor eax, eax     ; this combination of asm avoids nulls in bytecode
	inc eax
	xor ebx, ebx
	add bl, 7
	int 0x80
buf:                ; let this offset be start of bytes that will be marked as tainted, e.g. input from network ; format [sizeof (local) + &evil_code]; sizeof (buf db) = 9
 	;db 0x55, 0x66, 0x77, 0x00  ; this will give legit exit code in combo with commenting out call prepBuf
 	db 0x55, 0x66, 0x77, 0x88  ;, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa; junk to change value in vuln_obj
	db 0xca, 0xfe, 0xfe, 0xed  ; spot to store evil_retaddr (&evilCode)
	db 0x00
		
skipBuf:
 	; call prepBuf and ret returned &vuln_obj to its pre call stack position (top)
	; call skipBuf put &buf on top of stack [so now: &buf; &vuln_obj ]
	; objLog (&buf)
	pop ebx         ; ebx = &evilCode + sizeof (&buf (source) ) [so now: &vuln_obj ]
	add ebx, 10     ; ebx = &evilCode + 10
	;pop eax         ; eax = &vuln_obj (destination) [so now: ]
	call objLog     ; ret_addr on top of stack  [so now: legit_retaddr]
	;call objCpy_stub ; ret_addr on top of stack  [so now: legit_retaddr]
	mov eax, 1
	mov ebx, 5
	int 0x80

; debug stubs
;prepBuf_stub:
;	ret
;objCpy_stub:
;	ret
; exit code should be 5

; modifies buf to contain proper address for evil_code
; this automates the process for each run, allows assumption that attacker sent proper attack string
; be able to over write buf properly
prepBuf:              ; write &evil_code into &(buf[4])
	; &evilCode        = esp + sizeof (call skipBuf) = esp + 5 = &evil_retaddr - ?
	mov esi, [esp]     ; ret_addr = &(call skipBuf) is at top of stack
	add esi, 5
	; fn* evil_retaddr = esp + sizeof (call skipBuf) + sizeof (evilCode) + offset within buf = esp + 5 + 10 = esp + 15 = &evilCode + 10
	mov edi, esi
	add edi, 10
	add edi, 4         ; offset within buf
	; evil_retaddr     = &evil_code
	mov [edi], esi
	ret
; exit code should be 5 and there should be a mem_map of cafefeed -> &evil_code

; objLog (ob)
objLog:             ; copies untrusted buf into a trusted local vuln_obj
	;push esp         ; debug, let's me see esp here, to see if we overwrite it
	;pop edi          ; debug, clear the stack entry
	push 0x99aabbcc  ; vuln_obj
	mov edi, esp     ; edi = &vuln_obj 
	;mov edi, eax     ; old objCpy dst addr (vuln_obj)
	mov esi, ebx     ; src addr (buf)
	xor eax, eax     ; clean up/zero out eax so cmp works
	mov ecx, 8       ; strlen (buf)
	cp_loop:         ; byte for byte, copy esi to edi, including final null terminator
		lodsb         ; mov eax, esi ; inc esi
		stosb         ; mov edi, eax ; inc edi
		loop cp_loop
	pop eax          ; clear earlier push
	xor eax, eax     ; clear eax to make reading debug output clearer
	ret              ; pop and jmp; this should use tainted value
; exit code should be 7; there should be a mem_map of cafefeed -> &evil_code; as well as stack 11223344 -> 55667788 and retaddr -> &evil_code

