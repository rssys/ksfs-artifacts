#include <linux/linkage.h>

SYM_FUNC_START(wasm_save_state)
	movq %r15, 0(%rdi)
	movq %r14, 8(%rdi)
	movq %r13, 16(%rdi)
	movq %r12, 24(%rdi)
	movq %rbp, 32(%rdi)
	movq %rbx, 40(%rdi)
	movq %rsp, 48(%rdi)
	movq (%rsp), %rax
	movq %rax, 56(%rdi)
	xorl %eax, %eax
	ret
SYM_FUNC_END(wasm_save_state)
