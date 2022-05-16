	.file	"case1.c"
	.text
	.section	.rodata
.LC0:
	.string	"%d\n"
.LC1:
	.string	"pause"
	.text
	.globl	main
	.type	main, @function
main:
.LFB6:
	.cfi_startproc
	endbr64
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$112, %rsp
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	movl	$0, -88(%rbp)
	leaq	-64(%rbp), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	gets@PLT
	leaq	-74(%rbp), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	gets@PLT
	leaq	-64(%rbp), %rax
	movq	%rax, %rdi
	call	strlen@PLT
	movl	%eax, -84(%rbp)
	leaq	-74(%rbp), %rax
	movq	%rax, %rdi
	call	strlen@PLT
	movl	%eax, -80(%rbp)
	movl	$0, -100(%rbp)
	jmp	.L2
.L7:
	movl	$0, -96(%rbp)
	movl	-100(%rbp), %eax
	movl	%eax, -92(%rbp)
	jmp	.L3
.L5:
	addl	$1, -96(%rbp)
	addl	$1, -92(%rbp)
.L3:
	movl	-96(%rbp), %eax
	cmpl	-80(%rbp), %eax
	jge	.L4
	movl	-96(%rbp), %eax
	cltq
	movzbl	-74(%rbp,%rax), %edx
	movl	-92(%rbp), %eax
	cltq
	movzbl	-64(%rbp,%rax), %eax
	cmpb	%al, %dl
	je	.L5
.L4:
	movl	-96(%rbp), %eax
	cmpl	-80(%rbp), %eax
	jne	.L6
	addl	$1, -88(%rbp)
.L6:
	addl	$1, -100(%rbp)
.L2:
	movl	-84(%rbp), %eax
	subl	-80(%rbp), %eax
	cmpl	%eax, -100(%rbp)
	jle	.L7
	movl	-88(%rbp), %eax
	movl	%eax, %esi
	leaq	.LC0(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	leaq	.LC1(%rip), %rdi
	call	system@PLT
	movl	$0, %eax
	movq	-8(%rbp), %rcx
	xorq	%fs:40, %rcx
	je	.L9
	call	__stack_chk_fail@PLT
.L9:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	 1f - 0f
	.long	 4f - 1f
	.long	 5
0:
	.string	 "GNU"
1:
	.align 8
	.long	 0xc0000002
	.long	 3f - 2f
2:
	.long	 0x3
3:
	.align 8
4:
