/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>
#include <kern/macro.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushq $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushq $0;							\
	pushq $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
   Find the PUSHA,POPA macros in kern/macro.h. Since amd64 doesn't support
   pusha,popa so you will find these macros handy.
 */
 
	/* whether or not to use error code found here:
	 * www3.cs.stonybrook.edu/~porter/courses/cse506/f14/ref/i386/s09_10.htm
	 */
	TRAPHANDLER_NOEC(handle_divide, T_DIVIDE)
	TRAPHANDLER_NOEC(handle_debug, T_DEBUG)
	TRAPHANDLER_NOEC(handle_nmi, T_NMI)
	TRAPHANDLER_NOEC(handle_brkpt, T_BRKPT)
	TRAPHANDLER_NOEC(handle_oflow, T_OFLOW)
	TRAPHANDLER_NOEC(handle_bound, T_BOUND)
	TRAPHANDLER_NOEC(handle_illop, T_ILLOP)
	TRAPHANDLER_NOEC(handle_device, T_DEVICE)
	TRAPHANDLER(handle_dblflt, T_DBLFLT)
	TRAPHANDLER(handle_tss, T_TSS)
	TRAPHANDLER(handle_segnp, T_SEGNP)
	TRAPHANDLER(handle_stack, T_STACK)
	TRAPHANDLER(handle_gpflt, T_GPFLT)
	TRAPHANDLER(handle_pgflt, T_PGFLT)
	TRAPHANDLER_NOEC(handle_fperr, T_FPERR)
	TRAPHANDLER(handle_align, T_ALIGN)
	TRAPHANDLER_NOEC(handle_mchk, T_MCHK)
	TRAPHANDLER_NOEC(handle_simderr, T_SIMDERR)
	TRAPHANDLER_NOEC(handle_syscall, T_SYSCALL)
	TRAPHANDLER_NOEC(handle_default, T_DEFAULT)
	
	// @@@ lab4 part, find definition in lib/trap.h
	TRAPHANDLER_NOEC(handle_irq0, IRQ_OFFSET)
	TRAPHANDLER_NOEC(handle_irq1, (IRQ_OFFSET+1))
	TRAPHANDLER_NOEC(handle_irq2, (IRQ_OFFSET+2))
	TRAPHANDLER_NOEC(handle_irq3, (IRQ_OFFSET+3))
	TRAPHANDLER_NOEC(handle_irq4, (IRQ_OFFSET+4))
	TRAPHANDLER_NOEC(handle_irq5, (IRQ_OFFSET+5))
	TRAPHANDLER_NOEC(handle_irq6, (IRQ_OFFSET+6))
	TRAPHANDLER_NOEC(handle_irq7, (IRQ_OFFSET+7))
	TRAPHANDLER_NOEC(handle_irq8, (IRQ_OFFSET+8))
	TRAPHANDLER_NOEC(handle_irq9, (IRQ_OFFSET+9))
	TRAPHANDLER_NOEC(handle_irq10, (IRQ_OFFSET+10))
	TRAPHANDLER_NOEC(handle_irq11, (IRQ_OFFSET+11))
	TRAPHANDLER_NOEC(handle_irq12, (IRQ_OFFSET+12))
	TRAPHANDLER_NOEC(handle_irq13, (IRQ_OFFSET+13))
	TRAPHANDLER_NOEC(handle_irq14, (IRQ_OFFSET+14))
	TRAPHANDLER_NOEC(handle_irq15, (IRQ_OFFSET+15))



/*
 * Lab 3: Your code here for _alltraps
 *
 * Hint: Be sure to review the x64 calling convention from lab1
 *       for how to pass a pointer to the trapframe.
 */

_alltraps:
	
	/*xorq %rax,%rax
	 *movw %ds, %ax
	 *push %ds
	 *movw %es, %ax
	 *push %es
	 */ // this is all wrong, I cannot mess rax
	 
	subq $16, %rsp
	movq $0, 0(%rsp)
	movq $0, 8(%rsp)
	movw %es, 0(%rsp)
	movw %ds, 8(%rsp)
	PUSHA
	
	movw $GD_KD, %ax
	movw %ax, %ds
	movw %ax, %es
	
	// @@@ move the first arg into rdi, as the struct Trapframe *tf
	// @@@ http://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/
	
	movq %rsp, %rdi
	call trap


