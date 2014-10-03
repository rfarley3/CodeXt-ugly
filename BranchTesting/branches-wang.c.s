# Modified by shellforge v0.1.15
	.file	"branches-wang.c"
	.text
	.p2align 2,,3
.globl main
	.type	main, @function
main:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%edi
	pushl	%esi
	push %ebx
	call .L649
.L649:
	popl %ebx
	addl $[main-.L649],%ebx
	xorl	%edx, %edx
	movl	$5, %edi
	leal	.LC0@GOTOFF(%ebx), %esi
	movl	%edi, %eax
	movl	%edx, %ecx
#APP
# 492 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov %esi,%ebx
	int $0x80
	popl %ebx
# 0 "" 2
#NO_APP
	movl	%eax, %edi
	incl	%eax
	je	.L10
.L2:
	leal	-13(%ebp), %ecx
	movl	$1, %edx
	movl	$3, %eax
#APP
# 490 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov %edi,%ebx
	int $0x80
	popl %ebx
# 0 "" 2
#NO_APP
	decl	%eax
	je	.L3
	movl	%edx, %eax
#APP
# 449 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov $-2,%ebx
	int $0x80
	popl %ebx
# 0 "" 2
#NO_APP
.L3:
	movb	-13(%ebp), %al
	cmpb	$9, %al
	jle	.L4
	movb	$2, %dl
.L5:
	movsbl	%dl,%edx
	incl	%edx
.L7:
	movl	$6, %eax
#APP
# 493 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov %edi,%ebx
	int $0x80
	popl %ebx
# 0 "" 2
#NO_APP
	movl	$1, %eax
#APP
# 449 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov %edx,%ebx
	int $0x80
	popl %ebx
# 0 "" 2
#NO_APP
	xorl	%eax, %eax
	addl	$16, %esp
	popl	%ebx
	popl	%esi
	popl	%edi
	leave
	ret
	.p2align 2,,3
.L4:
	testb	%al, %al
	js	.L11
	movb	$1, %dl
	jmp	.L5
	.p2align 2,,3
.L10:
	movl	$1, %eax
#APP
# 449 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov $-1,%ebx
	int $0x80
	popl %ebx
# 0 "" 2
#NO_APP
	jmp	.L2
	.p2align 2,,3
.L11:
	xorl	%edx, %edx
	jmp	.L7
.LC0:
	.string	"/dev/shm/dasosdatafile"
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 4.4.4-14ubuntu5) 4.4.5"
	.section	.note.GNU-stack,"",@progbits
