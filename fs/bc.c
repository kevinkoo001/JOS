
#include "fs.h"

// Return the virtual address of this disk block.
void*
diskaddr(uint64_t blockno)
{
	if (blockno == 0 || (super && blockno >= super->s_nblocks))
		panic("bad block number %08x in diskaddr", blockno);
	return (char*) (DISKMAP + blockno * BLKSIZE);
}

// Fault any disk block that is read in to memory by
// loading it from disk.
static void
bc_pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint64_t blockno = ((uint64_t)addr - DISKMAP) / BLKSIZE;
	int r;

	// Check that the fault was within the block cache region
	if (addr < (void*)DISKMAP || addr >= (void*)(DISKMAP + DISKSIZE))
		panic("page fault in FS: eip %08x, va %08x, err %04x",
		      utf->utf_rip, addr, utf->utf_err);

	// Sanity check the block number.
	if (super && blockno >= super->s_nblocks)
		panic("reading non-existent block %08x\n", blockno);

	// Allocate a page in the disk map region, read the contents
	// of the block from the disk into that page.
	// Hint: first round addr to page boundary.
	//
	// LAB 5: you code here:
	
	// @@@ Note that addr may not be aligned to a block boundary 
	void *diskBlockVa = ROUNDDOWN(diskaddr(blockno), BLKSIZE);
	
	// @@ int sys_page_alloc(envid_t envid, void *va, int perm) @lib\syscall.c
	envid_t cur_id = sys_getenvid();
	if (sys_page_alloc(cur_id, diskBlockVa, PTE_P | PTE_U | PTE_W) < 0)
		panic("bc_pgfault: alloc for diskBlock failed!");

	// @@@ Note that ide_read operates in sectors, not blocks
	// @@@ BLKSECTS, BLKSIZE, SECTSIZE @inc\fs.h and @fs\fs.h
	// @@@ int ide_read(uint32_t secno, void *dst, size_t nsecs) @fs\ide.c;
	if ((r = ide_read(blockno*BLKSECTS, diskBlockVa, BLKSIZE/SECTSIZE)) < 0)
		panic("bc_pgfault: reading the contents of the block failed!");

}


void
bc_init(void)
{
	struct Super super;
	set_pgfault_handler(bc_pgfault);

	// cache the super block by reading it once
	memmove(&super, diskaddr(1), sizeof super);
}

