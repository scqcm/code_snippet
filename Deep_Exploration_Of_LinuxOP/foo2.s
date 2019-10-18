	.file	"foo2.c"
	.globl	foo2
	.data
	.align 4
	.type	foo2, @object
	.size	foo2, 4
foo2:
	.long	10
	.text
	.globl	foo2_func
	.type	foo2_func, @function
foo2_func:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	foo2(%rip), %eax
	movl	%eax, -4(%rbp)
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	foo2_func, .-foo2_func
	.ident	"GCC: (GNU) 4.8.5 20150623 (Red Hat 4.8.5-36)"
	.section	.note.GNU-stack,"",@progbits
