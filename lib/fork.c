// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	// @@@ cprintf("fault %x\n", addr);
  
	// @@@ THIS PART IS IMPORTANT!! OTHERWISE IT WILL ENCOUNTER ANOTHER PAGE FAULT!!
	void* addr_align = (void*)ROUNDDOWN(utf->utf_fault_va, PGSIZE);
	uint64_t pn = ((uint64_t)addr) / PGSIZE;
	
	if (!((uvpt[pn] & PTE_COW) && (err & FEC_WR)))
		panic("pgfault: not COW page or not write page fault! fault addr: %x", addr);
	
	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.
	
	// LAB 4: Your code here.
	
	envid_t cur_id = sys_getenvid();
	// @@@ Allocate a new page, map it at PFTEMP
	// @@@ (1) int sys_page_alloc(envid_t envid, void *va, int perm);
	if ((r = sys_page_alloc(cur_id, PFTEMP, PTE_P|PTE_U|PTE_W)) < 0)
		panic("pgfault: allocating at %x in page fault handler: %e", addr, r);
	
	// @@@ Copy the data from the old page to the new page
	// @@@ void* memcpy(void *dst, const void *src, size_t len);
	memcpy(PFTEMP, addr_align, PGSIZE);
	
	// @@@ Move the new page to the old page's address
	// @@@ (2) int sys_page_map(envid_t srcenv, void *srcva, envid_t dstenv, void *dstva, int perm);
	if ((r = sys_page_map(cur_id, PFTEMP, cur_id, addr_align, PTE_P|PTE_U|PTE_W)) < 0)
		panic("pgfault: moving %x to PFTEMP in page fault handler: %e", addr, r);
	
	// @@@ Clear the temporary pte in PFTEMP
	// @@@ (3) int sys_page_unmap(envid_t envid, void *va)
	if ((r = sys_page_unmap(cur_id, PFTEMP)) < 0)
		panic("pgfault: unmap PFTEMP failed! %e", r);
	
	//panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	uint64_t pn_64 = pn;
	void* addr = (void*)(pn_64 * PGSIZE);
  
	envid_t cur_id = sys_getenvid();
	int perm = uvpt[pn_64] & 0xfff;
	
	// @@@ lab 5
	if (uvpt[pn_64] & PTE_SHARE)
	{
		if ((r = sys_page_map(cur_id, addr, envid, addr, PTE_SYSCALL)) < 0)
			panic("duppage: mapping 0x%x failed!: %e", addr, r);
		// @@@ cprintf("duppage: enter the share if, addr is %x\n", addr);
	}
	
	// @@@ Check if va is writable/COW-able
	else if ((uvpt[pn_64] & PTE_W) || (uvpt[pn_64] & PTE_COW))
	{
		// @@@ cprintf("duppage: enter the COW if, addr is %x\n", addr);
		// @@@ map the page copy-on-write into the address space of the child
		if ((r = sys_page_map(cur_id, addr, envid, addr, PTE_P | PTE_U | PTE_COW)) < 0)
			panic("duppage: mapping 0x%x failed!: %e", addr, r);
		// @@@ remap the page copy-on-write in its own address space, in case PTE_COW bit is not set in parent pte
		// @@@ cannot include perm here because we don't want child to have PTE_W
		if ((r = sys_page_map(cur_id, addr, cur_id, addr, PTE_P | PTE_U | PTE_COW)) < 0)
			panic("duppage: mapping 0x%x failed!: %e", addr, r);
	}
	else
	{
		// @@@ copy parent's pte to child
		if ((r = sys_page_map(cur_id, addr, envid, addr, PTE_P | PTE_U | perm)) < 0)
			panic("duppage: map %x failed!: %e", addr, r);
	}

	//panic("duppage not implemented");
	return 0;
}

/*
// @@@ dumb duppage
static void
duppage(envid_t dstenv, void *addr)
{
	int r;

	// This is NOT what you should do in your fork.
	if ((r = sys_page_alloc(dstenv, addr, PTE_P|PTE_U|PTE_W)) < 0)
		panic("sys_page_alloc: %e", r);
	if ((r = sys_page_map(dstenv, addr, 0, UTEMP, PTE_P|PTE_U|PTE_W)) < 0)
		panic("sys_page_map: %e", r);
	memmove(UTEMP, addr, PGSIZE);
	if ((r = sys_page_unmap(0, UTEMP)) < 0)
		panic("sys_page_unmap: %e", r);
}*/

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	envid_t child_env;
	uintptr_t addr;
	envid_t cur_id = sys_getenvid();
	
	// @@@ allocate pgfault for current enviroment
	set_pgfault_handler(pgfault);
	
	child_env = sys_exofork();
	if (child_env < 0)
		panic("fork: create new env failed!\n");
	if (child_env == 0) {
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid (it refers to the parent!).
		// Fix it and return 0.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}
	
	// @@@ allocate the user exception stack for child environment
	if (sys_page_alloc(child_env, (void*)(UXSTACKTOP-PGSIZE), PTE_P | PTE_U | PTE_W) < 0)
		panic("fork: alloc exception stack failed!");
	
	// @@@ for parent:
	// @@@ PGNUM(la) in inc/mmu.h
	//cprintf("Before enter for\n");
	// @@@ this is the tricky part, copied from dumbfork
	// @@@ extern unsigned char end[];
	//cprintf("fork: the end of envid %x is %x\n", cur_id, end);
	for (addr = UTEXT; addr < (uintptr_t)(USTACKTOP - PGSIZE); addr += PGSIZE)
	{
		/*if ((uvpml4e[VPML4E(addr)] & PTE_P) && (uvpde[VPDPE(addr)] & PTE_P) && (uvpd[VPD(addr)] & PTE_P) && (uvpt[PGNUM(addr)] & (PTE_P | PTE_U)))
			duppage(child_env, PGNUM(addr));*/
		if (!(uvpml4e[VPML4E(addr)] & PTE_P))
		{
			addr += (0x7ffffff << 12);
			continue;
		}
		if (!(uvpde[VPDPE(addr)] & PTE_P))
		{
			addr += (0x3ffff << 12);
			continue;
		}
		if (!(uvpd[VPD(addr)] & PTE_P))
		{
			addr += (0x1ff << 12);
			continue;
		}
		if ((uvpt[PGNUM(addr)] & (PTE_P | PTE_U)))
			duppage(child_env, PGNUM(addr));
	}
	
	/*duppage(child_env, PGNUM(0x800000));
	duppage(child_env, PGNUM(0x801000));
	duppage(child_env, PGNUM(0x802000));
	duppage(child_env, PGNUM(0x803000));
	duppage(child_env, PGNUM(0x804000));*/
	//duppage(child_env, PGNUM(0xef7fd000));
	
	// @@@ copy stack from parent to child
	if (sys_page_alloc(cur_id, PFTEMP, PTE_P|PTE_U|PTE_W) < 0)
		panic("fork: allocating PFTEMP failed!");
	memcpy((void*)PFTEMP, (void*)(USTACKTOP - PGSIZE), PGSIZE);
	
	if (sys_page_map(cur_id, PFTEMP, child_env, (void*)(USTACKTOP - PGSIZE), PTE_W | PTE_U | PTE_P) < 0)
 		panic("fork: map PFTEMP to child's stack failed!");
	
	if (sys_page_unmap(cur_id, (void*)PFTEMP) < 0)
		panic("fork: ummap PFTEMP failed!");
	
	// @@@ mark it runnable
	if ((sys_env_set_status(child_env, ENV_RUNNABLE)) < 0)
		panic("fork: set runnable failed!\n");
	
	// @@@ lab 5: move this to here, invoke sys_env_set_pgfault_upcall after copy memory from parent
	// @@@ set the user page fault entrypoint
	extern void _pgfault_upcall(void);
	//cprintf("fork: gonna call sys_env_set_pgfault_upcall!\n");
	if (sys_env_set_pgfault_upcall(child_env, _pgfault_upcall) < 0)
		panic("fork: upcall failed!");
	
	// cprintf("fork: finished!\n");
	return child_env;
	
	//panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
