# Modified by shellforge v0.1.15
# modified by RJF
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
	call .L649     # get a relative addr       
.L649:
	popl %ebx      # now have relative addr in ebx
	addl $[main-.L649],%ebx    
	xorl	%edx, %edx
	movl	$5, %edi
	leal	.LC0@GOTOFF(%ebx), %esi
	movl	%edi, %eax    # get 5 into eax (open)
	movl	%edx, %ecx
#APP
# 492 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov %esi,%ebx
	int $0x80              # open
	popl %ebx
# 0 "" 2
#NO_APP
	movl	%eax, %edi       # edi is fd
	incl	%eax             # if (fd + 1) == 0 [eg if fd == -1] then the zeroflag would be set
	jne	.L2              # jmp to L10 (exit -1) if zeroflag is set, else L2
.L10:
   movl  $1, %eax
#APP
# 449 "shellforge/include/sfsyscall.h" 1
   pushl %ebx
   mov $-1,%ebx
   int $0x80                # exit -1
   popl %ebx
# 0 "" 2
#NO_APP
.L2:
	leal	-13(%ebp), %ecx   # ecx now holds &x [-13(%ebp) eq ebp-0x9]
	movl	$1, %edx
	movl	$3, %eax          #  get 3 into eax (read)
#APP
# 490 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov %edi,%ebx
	int $0x80         # read
	popl %ebx
# 0 "" 2
#NO_APP
	decl	%eax        # eax is bytes read, which should eq 1, so 1-1 == 0,  
	je	.L3            # jmp L3 if read ok
	movl	%edx, %eax  # set eax to 1
#APP
# 449 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov $-2,%ebx
	int $0x80         # exit -2
	popl %ebx
# 0 "" 2
#NO_APP
.L3:
   xor %edx,%edx           # y = 0
   xor %ecx,%ecx           # z = 0
   inc %ecx                # z = 1
	movb	-13(%ebp), %al    # al = x
	cmpb	$56, %al          # cmpb s2, s1# s1-s2# x-56
	jle	.L4               # jmp L4 if (x-56)<=0 aka '[012345678]'(don't jump if x>=57 aka '9')
	movb	$2, %dl           # dl = y = 2
   jmp .L11
.L4:
   cmpb $48, %al           # x-48 #testb  %al, %al          # test al,al is al&al #equiv to cmpb al,$0# 0-al
   jle  .L11               # jmp L11 if (x-48)<=0 aka '0' (don't jump if x>=49 aka '[12345678]') #js  .L11   # jmp L11 if signed/negative/x < 0 (don't jmp if x>=0)
   movb  $1, %dl           # y = 1
.L11:
   cmpb $0, %dl            # dl-0 RJF
   jne .L12                # jump L12 if y != 0 RJF (don't jump if y==0)
   movb $0, %cl            # z = 0
.L12:
   #if (y==1 && z==0) z=4
   cmpb $1, %dl
   jne .L5                 # jmp if y!=1
   cmpb $0, %cl
   jne .L5                 # jmp if z!=0 (don't jump if y==1&&z==0)
   movb $4, %cl
.L5:
   add %ecx,%edx           # y = y + z
	movl	$6, %eax          # set eax to 6 (close)
#APP
# 493 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov %edi,%ebx
	int $0x80               # close (fd) aka close (edi)
	popl %ebx
# 0 "" 2
#NO_APP
	movl	$1, %eax          # set eax to 1 (exit)
#APP
# 449 "shellforge/include/sfsyscall.h" 1
	pushl %ebx
	mov %edx,%ebx
	int $0x80               # exit y+z
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

.LC0:
	.string	"/dev/shm/dasosdatafile"
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 4.4.4-14ubuntu5) 4.4.5"
	.section	.note.GNU-stack,"",@progbits
