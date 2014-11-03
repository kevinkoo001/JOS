/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

	// LAB 3: Your code here.
	
	#ifdef DEBUG
	cprintf("sys_cputs: curenv - %x, *s - %s, len - %d\n", curenv, *s, len);
	#endif
	
	// @@@ Defined at kern\pmap.c
	//cprintf("sys_cputs: s: %x len: %x\n", s, len);
	user_mem_assert(curenv, (char*)s, len, 0);

	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.

	// LAB 4: Your code here.
	
	struct Env* newEnv;
	// @@@ current->env_id is a parent id of this fork
	if (env_alloc(&newEnv, curenv->env_id) < 0)
		return -E_NO_FREE_ENV;
	
	// @@@ Left as env_alloc created it but status
	newEnv->env_status = ENV_NOT_RUNNABLE;
	
	// @@@ Copy the register set from the current environment
	newEnv->env_tf = curenv->env_tf;
	//newEnv->env_tf.tf_regs = curenv->env_tf.tf_regs;
	
	// @@@ Tweaked so sys_exofork will appear to return 0?
	newEnv->env_tf.tf_regs.reg_rax = 0;
	// cprintf("sys_exofork: done! envid: %x\n", newEnv->env_id);
	return newEnv->env_id;
	
	// panic("sys_exofork not implemented");
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid. (OK)
//	-E_INVAL if status is not a valid status for an environment. (OK)
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.

	// LAB 4: Your code here.
	struct Env* newEnv;
	if(envid2env(envid, &newEnv, 1) < 0) {
		//cprintf("sys_env_set_status: env does not exist!\n");
		return -E_BAD_ENV;
	}
	
	if(!(status & ENV_RUNNABLE) && !(status & ENV_NOT_RUNNABLE)) {
		//cprintf("sys_env_set_status: env status error! status %x\n", status);
		return -E_INVAL;
	}
	
	newEnv->env_status = status;
	return 0;
	
	// panic("sys_env_set_status not implemented");
}

// Set envid's trap frame to 'tf'.
// tf is modified to make sure that user environments always run at code
// protection level 3 (CPL 3) with interrupts enabled.		done
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
{
	// LAB 5: Your code here.
	// Remember to check whether the user has supplied us with a good
	// address!
	struct Env* newEnv;
	
	if (envid2env(envid, &newEnv, 1) < 0)
		return -E_BAD_ENV;
	
	user_mem_assert(newEnv, tf, sizeof(struct Trapframe),PTE_U | PTE_P);
	newEnv->env_tf = *tf;
	
	// @@@ prevent malicious/unintentional trapframe
	// @@@ copied from env_alloc()@env.c
	newEnv->env_tf.tf_ds = GD_UD | 3;
	newEnv->env_tf.tf_es = GD_UD | 3;
	newEnv->env_tf.tf_ss = GD_UD | 3;
	newEnv->env_tf.tf_cs = GD_UT | 3;
	
	return 0;
	//panic("sys_env_set_trapframe not implemented");
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	struct Env* e;
	if(envid2env(envid, &e, 1) < 0)
		return -E_BAD_ENV;
	
	e->env_pgfault_upcall = func;
	return 0;
	// panic("sys_env_set_pgfault_upcall not implemented");
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid. (OK)
//	-E_INVAL if va >= UTOP, or va is not page-aligned. (OK)
//	-E_INVAL if perm is inappropriate (see above). (OK?)
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables. (OK)
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!

	// LAB 4: Your code here.
	
	// @@@ Check environment 
	struct Env* newEnv;
	if(envid2env(envid, &newEnv, 1) < 0)
		return -E_BAD_ENV;
	
	// @@@ Check va
	if((uintptr_t)va >= UTOP || ROUNDDOWN((uintptr_t)va, PGSIZE) != (uintptr_t)va)
		return -E_INVAL;
	
	// @@@ Check permission ??
	if(!(perm & PTE_U) || !(perm & PTE_P) || (perm & !PTE_SYSCALL))
		return -E_INVAL;
	
	// @@@ Allocate memory if page is successfully allocated
	struct PageInfo* newPage = page_alloc(ALLOC_ZERO);
	if(newPage == NULL)
		return -E_NO_MEM;
	if (page_insert(newEnv->env_pml4e, newPage, va, perm) < 0) {
		page_free(newPage);
		return -E_NO_MEM;
	}
	
	return 0;
	
	//panic("sys_page_alloc not implemented");
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them. 
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned. (OK)
//	-E_INVAL is srcva is not mapped in srcenvid's address space. (OK)
//	-E_INVAL if perm is inappropriate (see sys_page_alloc). (OK)
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space. (OK)
//	-E_NO_MEM if there's no memory to allocate any necessary page tables. (OK)
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.

	// LAB 4: Your code here.
	
	// @@@ Check srcenvid/dstenvid
	// [TODO] How to check if caller doesn't have permission to change one of them
	struct Env* srcEnv;
	struct Env* dstEnv;
	if(envid2env(srcenvid, &srcEnv, 1) < 0 || envid2env(dstenvid, &dstEnv, 1) < 0)
		return -E_BAD_ENV;
	
	// @@@ Check srcva/dstva
	if((uintptr_t)srcva >= UTOP || ROUNDDOWN((uintptr_t)srcva, PGSIZE) != (uintptr_t)srcva || (uintptr_t)dstva >= UTOP || ROUNDDOWN((uintptr_t)dstva, PGSIZE) != (uintptr_t)dstva)
		return -E_INVAL;
		
	// @@@ Check if srcva is not mapped in srcenvid's address space
	pte_t* pte;
	struct PageInfo* pp = page_lookup(srcEnv->env_pml4e, srcva, &pte);
	if(pp == NULL)
		return -E_INVAL;
		
	// @@@ Check permission
	if(!(perm & PTE_U) || !(perm & PTE_P) || (perm & !PTE_SYSCALL))
		return -E_INVAL;
	
	// @@@ Check if (perm & PTE_W), but srcva is read-only in srcenvid's addr space
	if((perm & PTE_W) && (!(*pte & PTE_W)))
		return -E_INVAL;
		
	// @@@ Check memory space for page table
	if(page_insert(dstEnv->env_pml4e, pp, dstva, perm) < 0)
		return -E_NO_MEM;
		
	return 0;
	
	//panic("sys_page_map not implemented");
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid. (OK)
//	-E_INVAL if va >= UTOP, or va is not page-aligned. (OK)
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().

	// LAB 4: Your code here.
	struct Env* newEnv;
	
	// @@@ Check env and permission
	if(envid2env(envid, &newEnv, 1) < 0)
		return -E_BAD_ENV;
	
	// @@@ Check va
	if((uintptr_t)va >= UTOP || ROUNDDOWN((uintptr_t)va, PGSIZE) != (uintptr_t)va)
		return -E_INVAL;
	
	// @@ Unmap the page, note that page_remove() returns nothing
	page_remove(newEnv->env_pml4e, va);
	return 0;
	
	// panic("sys_page_unmap not implemented");
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.				done
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,		done
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.					done
//	-E_INVAL if srcva < UTOP and perm is inappropriate						maybe done
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's		done
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the				done
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's			
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.
	//cprintf("sys_ipc_try_send: enter!\n");
	struct Env* newEnv;
	struct PageInfo* pp;
	
	// @@@ do not check env and permission
	// @@@ -E_BAD_ENV if environment envid doesn't currently exist.
	if (envid2env(envid, &newEnv, 0) < 0)
		return -E_BAD_ENV;
	
	// @@@ -E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
	if (!newEnv->env_ipc_recving)
		return -E_IPC_NOT_RECV;
	
	newEnv->env_ipc_perm = 0;
	// @@@ check if srcva < UTOP
	if ((uintptr_t)srcva < UTOP)
	{
		// @@@ -E_INVAL if srcva < UTOP but srcva is not page-aligned.
		if (srcva != ROUNDDOWN(srcva, PGSIZE))
			return -E_INVAL;
		// @@@ -E_INVAL if srcva < UTOP and perm is inappropriate
		// @@@ copied from sys_page_alloc
		if(!(perm & PTE_U) || !(perm & PTE_P) || (perm & !PTE_SYSCALL))
			return -E_INVAL;
		// @@@ -E_INVAL if srcva < UTOP but srcva is not mapped in the caller's address space.
		pte_t* pte;
		if (!(pp = page_lookup(curenv->env_pml4e, srcva, &pte)))
			return -E_INVAL;
		// @@@ -E_INVAL if (perm & PTE_W), but srcva is read-only in the current environment's address space.
		if ((perm & PTE_W) && !(*pte & PTE_W))
			return -E_INVAL;
		// @@@ -E_NO_MEM if there's not enough memory to map srcva in envid's address space.
		if ((uintptr_t)newEnv->env_ipc_dstva < UTOP)
		{
			if (newEnv->env_ipc_dstva != ROUNDDOWN(newEnv->env_ipc_dstva, PGSIZE))
				return -E_INVAL;
			// @@@ used to set det va as srcva too, cause big trouble.
			if (page_insert(newEnv->env_pml4e, pp, newEnv->env_ipc_dstva, perm) < 0)
				return -E_NO_MEM;
			//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
			newEnv->env_ipc_perm = perm;
		}
		else
			return -E_INVAL;
	}
	
	// Otherwise, the send succeeds, and the target's ipc fields are
	// updated as follows:
	//    env_ipc_recving is set to 0 to block future sends;
	//    env_ipc_from is set to the sending envid;
	//    env_ipc_value is set to the 'value' parameter;
	//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.		this is done inside if loop
	// The target environment is marked runnable again, returning 0
	// from the paused sys_ipc_recv system call.  (Hint: does the
	// sys_ipc_recv function ever actually return?)
	newEnv->env_ipc_recving = 0;
	newEnv->env_ipc_from = curenv->env_id;
	newEnv->env_ipc_value = value;
	newEnv->env_status = ENV_RUNNABLE;
	// @@@ (Hint: does the sys_ipc_recv function ever actually return?)
	newEnv->env_tf.tf_regs.reg_rax = 0;
	
	return 0;
	//panic("sys_ipc_try_send not implemented");
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
	//cprintf("sys_ipc_recv: enter!\n");
	if ((uintptr_t)dstva < UTOP)
	{
		if (dstva != ROUNDDOWN(dstva, PGSIZE))
			return -E_INVAL;
		else
			curenv->env_ipc_dstva = dstva;
	}
	
	curenv->env_ipc_recving = 1;
	curenv->env_status = ENV_NOT_RUNNABLE;
	// @@@ this function doesn't return either
	curenv->env_tf.tf_regs.reg_rax = 0;
	sys_yield();
	//panic("sys_ipc_recv not implemented");
	return 0;
}




// Dispatches to the correct kernel function, passing the arguments.
int64_t
syscall(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.
	
	//panic("syscall not implemented");
	uint64_t ret;
	
	#ifdef DEBUG
	cprintf("[DEBUG3] syscall(): Syscallno %x\n", syscallno);
	#endif
	
	switch (syscallno) {
		case SYS_cputs:
			sys_cputs((char*)a1, a2);
			return 0;
		case SYS_cgetc:
			ret = sys_cgetc();
			return ret;
		case SYS_getenvid:
			ret = sys_getenvid();
			return ret;
		case SYS_env_destroy:
			if(sys_env_destroy(a1) == 0)
				return 0;
			return -E_NO_SYS;
		case NSYSCALLS:
			return -E_INVAL;
		// @@@ lab4 for round-robin scheduling
		case SYS_yield:
			sys_yield();
			return 0;
		case SYS_exofork:
			ret = sys_exofork();
			return ret;
		case SYS_env_set_status:
			ret = sys_env_set_status((envid_t)a1, (int)a2);
			return ret;
		case SYS_page_alloc:
			ret = sys_page_alloc((envid_t)a1, (void*)a2, (int)a3);
			return ret;
		case SYS_page_map:
			ret = sys_page_map((envid_t)a1, (void*)a2, (envid_t)a3, (void*)a4, (int)a5);
			return ret;
		case SYS_page_unmap:
			ret = sys_page_unmap((envid_t)a1, (void*)a2);
			return ret;
		case SYS_env_set_pgfault_upcall:
			ret = sys_env_set_pgfault_upcall((envid_t)a1, (void*)a2);
			return ret;
		// @@@ lab4 for ipc
		case SYS_ipc_try_send:
			ret = sys_ipc_try_send((envid_t)a1, (uint32_t)a2, (void*)a3, (unsigned)a4);
			return ret;
		case SYS_ipc_recv:
			ret = sys_ipc_recv((void*)a1);
			return ret;
		// @@@ lab5 for spawn
		case SYS_env_set_trapframe:
			ret = sys_env_set_trapframe((envid_t)a1, (struct Trapframe*)a2);
			return ret;
		// @@@ In case of other system call
		default:
			return -E_NO_SYS;
	}
}

