/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/mmu.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/kclock.h>
#include <kern/multiboot.h>
#include <kern/env.h>

#define BOOT_PAGE_TABLE_START 0xf0008000
#define BOOT_PAGE_TABLE_END   0xf000e000

// These variables are set by i386_detect_memory()
// @@@ size_t equals to uint64_t, defined in inc/types.h
size_t npages;			// Amount of physical memory (in pages)
static size_t npages_basemem;	// Amount of base memory (in pages)

// These variables are set in mem_init()
pml4e_t *boot_pml4e;		// Kernel's initial page directory
physaddr_t boot_cr3;		// Physical address of boot time page directory
struct PageInfo *pages;		// Physical page state array
static struct PageInfo *page_free_list;	// Free list of physical pages

// --------------------------------------------------------------
// Detect machine's physical memory setup.
// --------------------------------------------------------------

static int
nvram_read(int r)
{
	return mc146818_read(r) | (mc146818_read(r + 1) << 8);
}

// @@@ Base memory = 640KB
static void
multiboot_read(multiboot_info_t* mbinfo, size_t* basemem, size_t* extmem) {
	int i;

	memory_map_t* mmap_base = (memory_map_t*)(uintptr_t)mbinfo->mmap_addr;
 	memory_map_t* mmap_list[mbinfo->mmap_length/ (sizeof(memory_map_t))];

    cprintf("\ne820 MEMORY MAP\n");
    for(i = 0; i < (mbinfo->mmap_length / (sizeof(memory_map_t))); i++) {
    	memory_map_t* mmap = &mmap_base[i];

    	uint64_t addr = APPEND_HILO(mmap->base_addr_high, mmap->base_addr_low);
    	uint64_t len = APPEND_HILO(mmap->length_high, mmap->length_low);
        
        cprintf("size: %d, address: 0x%016x, length: 0x%016x, type: %x\n", mmap->size, 
                addr, len, mmap->type);

        if(mmap->type > 5 || mmap->type < 1)
        	mmap->type = MB_TYPE_RESERVED;
       
        //Insert into the sorted list
        int j = 0;
        for(;j<i;j++) {
        	memory_map_t* this = mmap_list[j];
        	uint64_t this_addr = APPEND_HILO(this->base_addr_high, this->base_addr_low);
        	if(this_addr > addr) {
        		int last = i+1;
        		while(last != j) {
        			*(mmap_list + last) = *(mmap_list + last - 1);
        			last--;
        		}
        		break; 
        	}
        }
        mmap_list[j] = mmap;  
    }
    cprintf("\n");
    
    // Sanitize the list
	for(i=1;i < (mbinfo->mmap_length / (sizeof(memory_map_t))); i++) {
		memory_map_t* prev = mmap_list[i-1];
		memory_map_t* this = mmap_list[i];

		uint64_t this_addr = APPEND_HILO(this->base_addr_high, this->base_addr_low);
        uint64_t prev_addr = APPEND_HILO(prev->base_addr_high, prev->base_addr_low);
        uint64_t prev_length = APPEND_HILO(prev->length_high, prev->length_low);
		uint64_t this_length = APPEND_HILO(this->length_high, this->length_low);

		// Merge adjacent regions with same type
		if(prev_addr + prev_length == this_addr && prev->type == this->type) {
			this->length_low = (uint32_t)prev_length + this_length;
			this->length_high = (uint32_t)((prev_length + this_length)>>32);
			this->base_addr_low = prev->base_addr_low;
			this->base_addr_high = prev->base_addr_high;
			mmap_list[i-1] = NULL;
		} else if(prev_addr + prev_length > this_addr) {
			//Overlapping regions
			uint32_t type = restrictive_type(prev->type, this->type);
			prev->type = type;
			this->type = type;
		}
	}

	for(i=0;i < (mbinfo->mmap_length / (sizeof(memory_map_t))); i++) {
		memory_map_t* mmap = mmap_list[i];
		if(mmap) {
			if(mmap->type == MB_TYPE_USABLE || mmap->type == MB_TYPE_ACPI_RECLM) {
				if(mmap->base_addr_low < 0x100000 && mmap->base_addr_high == 0)
					*basemem += APPEND_HILO(mmap->length_high, mmap->length_low);
				else
					*extmem += APPEND_HILO(mmap->length_high, mmap->length_low);
			}
		}
	}
}

static void
i386_detect_memory(void)
{
	size_t npages_extmem;
	size_t basemem = 0;
    size_t extmem = 0;

    // Check if the bootloader passed us a multiboot structure
    extern char multiboot_info[];
    uintptr_t* mbp = (uintptr_t*)multiboot_info;
	// @@@ Define multiboot type @kern/multiboot.h:63
    multiboot_info_t * mbinfo = (multiboot_info_t*)*mbp;
	
	// @@@ Define MB_FLAG_MMAP 0x40
    if(mbinfo && (mbinfo->flags & MB_FLAG_MMAP)) {
    	multiboot_read(mbinfo, &basemem, &extmem);
	} else {
		basemem = (nvram_read(NVRAM_BASELO) * 1024);
		extmem = (nvram_read(NVRAM_EXTLO) * 1024);
	}
    
    assert(basemem);
	npages_basemem = basemem / PGSIZE;
	npages_extmem = extmem / PGSIZE;

    // Calculate the number of physical pages available in both base
    // and extended memory.
    if (npages_extmem)
			// @@@ Define EXTPHYSMEM	0x100000
            npages = (EXTPHYSMEM / PGSIZE) + npages_extmem;
    else
            npages = npages_basemem;

    if(nvram_read(NVRAM_EXTLO) == 0xffff) {
        // EXTMEM > 16M in blocks of 64k
        size_t pextmem = nvram_read(NVRAM_EXTGT16LO) * (64 * 1024);
        npages_extmem = ((16 * 1024 * 1024) + pextmem - (1 * 1024 * 1024)) / PGSIZE;
    }

	// Calculate the number of physical pages available in both base
	// and extended memory.
	if (npages_extmem)
		npages = (EXTPHYSMEM / PGSIZE) + npages_extmem;
	else
		npages = npages_basemem;

	cprintf("Physical memory: %uM available, base = %uK, extended = %uK, npages = %d\n",
		npages * PGSIZE / (1024 * 1024),
		npages_basemem * PGSIZE / 1024,
		npages_extmem * PGSIZE / 1024, npages); // Missing arg added
    
    //JOS is hardwired to support only 256M of physical memory
    if(npages > ((255 * 1024 * 1024)/PGSIZE)) {
        npages = (255 * 1024 * 1024) / PGSIZE;
        cprintf("Using only %uK of the available memory.\n", npages * PGSIZE/1024);
    }

}


// --------------------------------------------------------------
// Set up memory mappings above UTOP.
// --------------------------------------------------------------

static void boot_map_region(pml4e_t *pml4e, uintptr_t va, size_t size, physaddr_t pa, int perm);
static void check_page_free_list(bool only_low_memory);
static void check_page_alloc(void);
static void check_boot_pml4e(pml4e_t *pml4e);
static physaddr_t check_va2pa(pde_t *pgdir, uintptr_t va);
static void page_check(void);
static void page_initpp(struct PageInfo *pp);
// This simple physical memory allocator is used only while JOS is setting
// up its virtual memory system.  page_alloc() is the real allocator.
//
// If n>0, allocates enough pages of contiguous physical memory to hold 'n'
// bytes.  Doesn't initialize the memory.  Returns a kernel virtual address.
//
// If n==0, returns the address of the next free page without allocating
// anything.
//
// If we're out of memory, boot_alloc should panic.
// This function may ONLY be used during initialization,
// before the page_free_list list has been set up.
static void *
boot_alloc(uint32_t n)
{
	static char *nextfree;	// virtual address of next byte of free memory
	char *result;

	// Initialize nextfree if this is the first time.
	// 'end' is a magic symbol automatically generated by the linker,
	// which points to the end of the kernel's bss segment:
	// the first virtual address that the linker did *not* assign
	// to any kernel code or global variables.
	
	if (!nextfree) {
		// @@@ end_debug = read_section_headers((0x10000+KERNBASE), (uintptr_t)end); @kern\init.c:37
        extern uintptr_t end_debug;
		// @@@ Rounding function to keep the multiple of PGSIZE @inc/types.h:64
		// @@@ nextfree: ptr to next free memory addr
		nextfree = ROUNDUP((char *) end_debug, PGSIZE);
		#ifdef DEBUG
		cprintf("[DEBUG] nextfree's value is: %u\n", nextfree);
		#endif
	}

	// Allocate a chunk large enough to hold 'n' bytes, then update
	// nextfree.  Make sure nextfree is kept aligned
	// to a multiple of PGSIZE.
	//
	// LAB 2: Your code here.
	if (n > 0)
	{
		result = nextfree;
		if (PADDR (ROUNDUP (nextfree + n, PGSIZE)) > (uint64_t)(npages * PGSIZE))
			panic("\n\tboot_alloc: Insufficient memory space to allocate\n\n");
		// @@@ Rounding function to keep the multiple of PGSIZE @inc/types.h:64
		nextfree = ROUNDUP (nextfree + n, PGSIZE);
		return result;
	}
	else if (n == 0)
		return nextfree;
	else
	{
		cprintf("boot_alloc(): Invalid memory allocation request!\n");
		return NULL;
	}
}

// Set up a four-level page table:
//    boot_pml4e is its linear (virtual) address of the root
//
// This function only sets up the kernel part of the address space
// (ie. addresses >= UTOP).  The user part of the address space
// will be setup later.
//
// From UTOP to ULIM, the user is allowed to read but not write.
// Above ULIM the user cannot read or write.
void
x64_vm_init(void)
{
	pml4e_t* pml4e;
	uint32_t cr0;
	uint64_t n;
	int r;
	struct Env *env;
	i386_detect_memory();

	//////////////////////////////////////////////////////////////////////
	// create initial page directory.
	// @@@ Commented out the next line due to complete implementation
	//panic("x64_vm_init: this function is not finished\n");
	
	// @@@ Initialize pml4e with 0s, page map level 4 index
	pml4e = boot_alloc(PGSIZE);
	memset(pml4e, 0, PGSIZE);
	// @@@ Define the starting address of the first table
	boot_pml4e = pml4e;
	// @@@ Store physical address in cr3
	boot_cr3 = PADDR(pml4e);
	#ifdef DEBUG
	cprintf("boot_cr3 is: %x\n", boot_cr3);
	#endif

	//////////////////////////////////////////////////////////////////////
	// Allocate an array of npages 'struct PageInfo's and store it in 'pages'.
	// The kernel uses this array to keep track of physical pages: for
	// each physical page, there is a corresponding struct PageInfo in this
	// array.  'npages' is the number of physical pages in memory.
	// Your code goes here:
	
	#ifdef DEBUG
	cprintf("[DEBUG] # of pages: %d, size of struct PageInfo is: %d bytes\n", npages, sizeof(struct PageInfo));
	#endif
	
	// @@@ Define ptr pointing to the first addr of the PageInfo structure, containing npages * 16K PageInfos
	pages = (struct PageInfo*)boot_alloc(npages * sizeof(struct PageInfo));

	//////////////////////////////////////////////////////////////////////
	// Make 'envs' point to an array of size 'NENV' of 'struct Env'.
	// LAB 3: Your code here.
	envs = (struct Env*) boot_alloc(NENV * sizeof(struct Env));
	
	//////////////////////////////////////////////////////////////////////
	// Now that we've allocated the initial kernel data structures, we set
	// up the list of free physical pages. Once we've done so, all further
	// memory management will go through the page_* functions. In
	// particular, we can now map memory using boot_map_region or page_insert
	page_init();
	check_page_free_list(1);
	check_page_alloc();
	page_check();
	

	//////////////////////////////////////////////////////////////////////
	// Now we set up virtual memory 
	//////////////////////////////////////////////////////////////////////
	// Map 'pages' read-only by the user at linear address UPAGES
	// Permissions:
	//    - the new image at UPAGES -- kernel R, us/er R
	//      (ie. perm = PTE_U | PTE_P)
	//    - pages itself -- kernel RW, user NONE
	// Your code goes here:
	boot_map_region(pml4e, UPAGES, ROUNDUP(sizeof(struct PageInfo) * npages, PGSIZE), PADDR(pages), PTE_U);

	//////////////////////////////////////////////////////////////////////
	// Map the 'envs' array read-only by the user at linear address UENVS
	// (ie. perm = PTE_U | PTE_P).
	// Permissions:
	//    - the new image at UENVS  -- kernel R, user R
	//    - envs itself -- kernel RW, user NONE
	// LAB 3: Your code here.
	boot_map_region(pml4e, UENVS, ROUNDUP(sizeof(struct Env) * NENV, PGSIZE), PADDR(envs), PTE_U);

	//////////////////////////////////////////////////////////////////////
	// Use the physical memory that 'bootstack' refers to as the kernel
	// stack.  The kernel stack grows down from virtual address KSTACKTOP.
	// We consider the entire range from [KSTACKTOP-PTSIZE, KSTACKTOP) 
	// to be the kernel stack, but break this into two pieces:
	//     * [KSTACKTOP-KSTKSIZE, KSTACKTOP) -- backed by physical memory
	//     * [KSTACKTOP-PTSIZE, KSTACKTOP-KSTKSIZE) -- not backed; so if
	//       the kernel overflows its stack, it will fault rather than
	//       overwrite memory.  Known as a "guard page".
	//     Permissions: kernel RW, user NONE
	// Your code goes here:
	boot_map_region(pml4e, KSTACKTOP-KSTKSIZE, KSTKSIZE, PADDR(bootstack), PTE_W);
	// @@@ we don't give any permission to this piece of memory. Update: according to TA, do not allocate this.
	//boot_map_region(pml4e, KSTACKTOP-PTSIZE, PTSIZE-KSTKSIZE, PADDR(bootstack+KSTKSIZE), 0);

	//////////////////////////////////////////////////////////////////////
	// Map all of physical memory at KERNBASE. We have detected the number
    // of physical pages to be npages.
	// Ie.  the VA range [KERNBASE, npages*PGSIZE) should map to
	//      the PA range [0, npages*PGSIZE - KERNBASE)
	// Permissions: kernel RW, user NONE
	// Your code goes here:
	boot_map_region(pml4e, KERNBASE, (npages * PGSIZE), 0x0, PTE_W);
	
	// Check that the initial page directory has been set up correctly.
	check_boot_pml4e(boot_pml4e);

	//////////////////////////////////////////////////////////////////////
	// Permissions: kernel RW, user NONE
	pdpe_t *pdpe = KADDR(PTE_ADDR(pml4e[1]));
	pde_t *pgdir = KADDR(PTE_ADDR(pdpe[0]));
	lcr3(boot_cr3);

	check_page_free_list(1);
	check_page_alloc();
	page_check();
	check_page_free_list(0);
}


// --------------------------------------------------------------
// Tracking of physical pages.
// The 'pages' array has one 'struct PageInfo' entry per physical page.
// Pages are reference counted, and free pages are kept on a linked list.
// --------------------------------------------------------------

//
// Initialize page structure and memory free list.
// After this is done, NEVER use boot_alloc again.  ONLY use the page
// allocator functions below to allocate and deallocate physical
// memory via the page_free_list.
//
	void
page_init(void)
{
	// The example code here marks all physical pages as free.
	// However this is not truly the case.  What memory is free?
	//  1) Mark physical page 0 as in use.
	//     This way we preserve the real-mode IDT and BIOS structures
	//     in case we ever need them.  (Currently we don't, but...)
	//  2) The rest of base memory, [PGSIZE, npages_basemem * PGSIZE)		* 1) page 0 in use, [0, PGSIZE)
	//     is free.															* 2) IO holes, from 0xA0000 - 0x100000 (pa!)
	//  3) Then comes the IO hole [IOPHYSMEM, EXTPHYSMEM), which must		* 	0xA0000 is IOPHYSMEM, 0x100000 is EXTPHYSMEM
	//     never be allocated.												* 3) initial boot page table, [BOOT_PAGE_TABLE_START, BOOT_PAGE_TABLE_END)
	//  4) Then extended memory [EXTPHYSMEM, ...).							* 4) kernel, from 0x100000 to end_debug
	//     Some of it is in use, some is free. Where is the kernel			* 5) BOOT_PAGE_TABLE_START=0xf0008000, BOOT_PAGE_TABLE_END=0xf000e000
	//     in physical memory?  Which pages are already in use for			* pay attention: 2) to 4) is consecutive.
	//     page tables and other data structures?
	//
	// Change the code to reflect this.
	// NB: DO NOT actually touch the physical memory corresponding to
	// free pages!
    // NB: Make sure you preserve the direction in which your page_free_list 
    // is constructed
	// NB: Remember to mark the memory used for initial boot page table i.e (va>=BOOT_PAGE_TABLE_START && va < BOOT_PAGE_TABLE_END) as in-use (not free)
	size_t i;
	struct PageInfo* last = NULL;
	extern uintptr_t end_debug;
	char*  first_free_page = (char *) boot_alloc(0);
	uintptr_t iova_st = (uintptr_t)pa2page((physaddr_t)IOPHYSMEM);
	//uintptr_t bptva_st = (uintptr_t)pa2page((physaddr_t)BOOT_PAGE_TABLE_START);
	//uintptr_t bptva_en = (uintptr_t)pa2page((physaddr_t)BOOT_PAGE_TABLE_END);
	
	#ifdef DEBUG
	cprintf("[DEBUG]\n");
	cprintf("  end_debug\t%08x (virt)\n", end_debug);
	cprintf("  BOOT_PAGE_TABLE_START\t%08x (virt)\n", BOOT_PAGE_TABLE_START);	// Should not be virtual address!!!
	cprintf("  BOOT_PAGE_TABLE_END\t%08x (virt)\n", BOOT_PAGE_TABLE_END);
	cprintf("  pages[0]\t%08x (pointer addr) %08x (page kva)\n", &pages[0], (uintptr_t)page2kva(&pages[0]));
	cprintf("  pages[1]\t%08x (pointer addr) %08x (page kva)\n", &pages[1], (uintptr_t)page2kva(&pages[1]));
	cprintf("  pages[2]\t%08x (pointer addr) %08x (page kva)\n", &pages[2], (uintptr_t)page2kva(&pages[2]));
	cprintf("  pages[%d]\t%08x (pointer addr) %08x (page kva)\n", npages, &pages[npages-1], (uintptr_t)page2kva(&pages[npages-1]));
	cprintf("  npages_basemem is: %08u\n", npages_basemem);
	cprintf("  iova_st\t%08x (virt)\n\n", (uintptr_t)iova_st);
	#endif
	
	// @@@ Marks all physical pages as free except 4 cases indicated above
	for (i = 0; i < npages; i++) {
		if((i == 0)
			|| (&pages[i] >= pa2page((physaddr_t)IOPHYSMEM) && (uintptr_t)page2kva(&pages[i]) < (uintptr_t)first_free_page)
			|| (&pages[i] >= pa2page((physaddr_t)0x8000) && &pages[i] < pa2page((physaddr_t)0xe000)))
		{
			#ifdef DEBUG
			// cprintf("[DEBUG] pages[%u]\t%08x (pointer addr) %08x (page kva) is set to be used!\n", i, &pages[i], (uintptr_t)page2kva(&pages[i]));
			#endif
			// @@@ pp_ref = 1: Page Not Available on the free page list
			pages[i].pp_ref = 1;
			pages[i].pp_link = NULL;
		}
		else
		{
			// @@@ pp_ref = 0: Page Available on the free page list
			pages[i].pp_ref = 0;
			pages[i].pp_link = NULL;
			if(last)
				last->pp_link = &pages[i];
			else
				// @@@ Execute only once at first, when pointing page_free_list to the first free page
				page_free_list = &pages[i];
			// @@@ Always points to the last page
			last = &pages[i];
		}
	}
	#ifdef DEBUG
	cprintf("[DEBUG] Page_init(): initialization finished!\n\n");
	uint64_t err_pp = 0x800432fff0;
	struct PageInfo* errpp = (struct PageInfo*)err_pp;
	cprintf("[DEBUG] errpp\t%08x (pointer addr) %08x %08x (page kva)\n", errpp, errpp->pp_link, (uintptr_t)page2kva(errpp));
	errpp = errpp->pp_link;
	cprintf("[DEBUG] errpp\t%08x (pointer addr) %08x %08x (page kva)\n", errpp, errpp->pp_link, (uintptr_t)page2kva(errpp));
	#endif
	/*cprintf("[DEBUG] First_free_page addr is: %08x (Physical addr: %08x)\n", first_free_page, PADDR(first_free_page));
	cprintf("[DEBUG] Boot PML4E is: %08x (Physical addr: %08x) \n", boot_pml4e, PADDR(boot_pml4e));
	cprintf("[DEBUG] PDPE: %08x \n", pml4e_walk(boot_pml4e, 0x0, 1));*/
}

//
// Allocates a physical page.  If (alloc_flags & ALLOC_ZERO), fills the entire
// returned physical page with '\0' bytes.  Does NOT increment the reference
// count of the page - the caller must do these if necessary (either explicitly
// or via page_insert).
//
// Be sure to set the pp_link field of the allocated page to NULL so
// page_free can check for double-free bugs.
//
// Returns NULL if out of free memory.
//
// Hint: use page2kva and memset
struct PageInfo *
page_alloc(int alloc_flags)
{
	// Fill this function in
	#ifdef DEBUG
	cprintf("[DEBUG] page_alloc(): start!\n");
	#endif
	
	struct PageInfo *newp;
	newp = page_free_list;
	if (newp == NULL)
	{
		#ifdef DEBUG
		cprintf("[DEBUG] page_alloc(): running out of memory!\n");
		#endif
		return NULL;
	}
	else
	{
		// @@@ Initialize the new page if required
		if (alloc_flags & ALLOC_ZERO)
			memset(page2kva(newp), 0, PGSIZE);
		// @@@ Move pointer to the next free page
		page_free_list = page_free_list->pp_link;
		newp->pp_link = NULL;
		return newp;
	}
	
}

//
// Initialize a Page structure.
// The result has null links and 0 refcount.
// Note that the corresponding physical page is NOT initialized!
//
	static void
page_initpp(struct PageInfo *pp)
{
	memset(pp, 0, sizeof(*pp));
}
//
// Return a page to the free list.
// (This function should only be called when pp->pp_ref reaches 0.)
//
void
page_free(struct PageInfo *pp)
{
	// Fill this function in
	// Hint: You may want to panic if pp->pp_ref is nonzero or
	// pp->pp_link is not NULL.
	#ifdef DEBUG
	cprintf("[DEBUG] page_free(): start!\n");
	#endif
	
	if (pp->pp_ref!=0 || pp->pp_link != NULL)
		panic("page_free: this page can not be freed!\n");
	
	pp->pp_link = page_free_list;
	page_free_list = pp;
}

//
// Decrement the reference count on a page,
// freeing it if there are no more refs.
//
void
page_decref(struct PageInfo* pp)
{
	if (--pp->pp_ref == 0)
		page_free(pp);
}
// Given a pml4 pointer, pml4e_walk returns a pointer
// to the page table entry (PTE) for linear address 'va'
// This requires walking the 4-level page table structure
//
// The relevant page directory pointer page(PDPE) might not exist yet.
// If this is true and create == false, then pml4e_walk returns NULL.
// Otherwise, pml4e_walk allocates a new PDPE page with page_alloc.
//       -If the allocation fails , pml4e_walk returns NULL.
//       -Otherwise, the new page's reference count is incremented,
// the page is cleared,
// and it calls the pdpe_walk() to with the given relevant pdpe_t pointer
// The pdpe_walk takes the page directory pointer and fetches returns the page table entry (PTE)
// If the pdpe_walk returns NULL 
//       -the page allocated for pdpe pointer (if newly allocated) should be freed.

// Hint 1: you can turn a Page * into the physical address of the
// page it refers to with page2pa() from kern/pmap.h.
//
// Hint 2: the x86 MMU checks permission bits in both the page directory
// and the page table, so it's safe to leave permissions in the page
// more permissive than strictly necessary.
//
// Hint 3: look at inc/mmu.h for useful macros that mainipulate page
// table, page directory,page directory pointer and pml4 entries.
//

pte_t *
pml4e_walk(pml4e_t *pml4e, const void *va, int create)
{
	pte_t *pte = NULL;
	pdpe_t *pdpe = NULL;
	
	// @@@ if pml4e exist, simply call pdpe_walk()
	if((pml4e[PML4(va)] & PTE_P))
	{
		#ifdef DEBUG
		cprintf("pml4e_walk: pdp table exist!\npml4e_walk: va: %x\n", va);
		cprintf("pml4e_walk: PML4(va) %x pml4e[PML4(va)]: %x\n", PML4(va), pml4e[PML4(va)]);
		cprintf("pml4e_walk: pdpe: %x, *pdpe %x \n" , pdpe, *pdpe);
		#endif
		pdpe = (pdpe_t *) KADDR(PTE_ADDR(pml4e[PML4(va)]));
		pte = pdpe_walk(pdpe, va, create);
		return pte;
	}
	else if(create == true)
	{
		struct PageInfo* NewPageForPDPT = page_alloc(ALLOC_ZERO);
		if (NewPageForPDPT == NULL)
			return NULL;
		NewPageForPDPT->pp_ref++;	// reference ctr incremented by 1
		// Assigned new page to *pml4e
		pml4e[PML4(va)] = (page2pa(NewPageForPDPT) & ~0xFFF) | PTE_USER;
		pdpe = (pdpe_t *) KADDR(PTE_ADDR(pml4e[PML4(va)]));
		#ifdef DEBUG
		cprintf("pml4e_walk: pdp table doesn't exist!\npml4e_walk: va: %x\n", va);
		cprintf("pml4e_walk: PML4(va) %x pml4e[PML4(va)]: %x\n", PML4(va), pml4e[PML4(va)]);
		cprintf("pml4e_walk: pdpe: %x, *pdpe %x \n" , pdpe, *pdpe);
		#endif
		pte = pdpe_walk(pdpe, va, create);
		if(pte == NULL) 
		{
			NewPageForPDPT->pp_ref--;
			page_free(NewPageForPDPT);
			pml4e[PML4(va)] = 0;
			return NULL;
		}
		return pte;
	}
	else
		// @@@ pml4e doesn't exist and create == false
		return NULL;
}


// Given a pdpe i.e page directory pointer pdpe_walk returns the pointer to page table entry
// The programming logic in this function is similar to pml4e_walk.
// It calls the pgdir_walk which returns the page_table entry pointer.
// Hints are the same as in pml4e_walk
pte_t *
pdpe_walk(pdpe_t *pdpe,const void *va,int create)
{
	pte_t *pte = NULL;
	pde_t *pde = NULL;
	
	// @@@ if pdpe exist, simply call pgdir_walk()
	if((pdpe[PDPE(va)] & PTE_P))
	{
		pde = (pde_t *) KADDR(PTE_ADDR(pdpe[PDPE(va)]));
		#ifdef DEBUG
		cprintf("pdpe_walk: &pdpe[PDPE(va)]: %x pdpe[PDPE(va)]: %x\n", &pdpe[PDPE(va)], pdpe[PDPE(va)]);
		cprintf("pdpe_walk: pde: %x, *pde %x \n" , pde, *pde);
		#endif
		pte = pgdir_walk(pde, va, create);
		return pte;
	}
	else if(create == true)
	{
		struct PageInfo* NewPageForPDT = page_alloc(ALLOC_ZERO);
		if (NewPageForPDT == NULL)
			return NULL;
		NewPageForPDT->pp_ref++;	// reference ctr incremented by 1
		// Assigned new page to *pdpe
		pdpe[PDPE(va)] = (page2pa(NewPageForPDT) & ~0xFFF) | PTE_USER;
		pde = (pde_t *) KADDR(PTE_ADDR(pdpe[PDPE(va)]));
		#ifdef DEBUG
		cprintf("pdpe_walk: &pdpe[PDPE(va)]: %x pdpe[PDPE(va)]: %x\n", &pdpe[PDPE(va)], pdpe[PDPE(va)]);
		cprintf("pdpe_walk: pde: %x, *pde %x \n" , pde, *pde);
		#endif
		pte = pgdir_walk(pde, va, create);
		if(pte == NULL) 
		{
			NewPageForPDT->pp_ref--;
			page_free(NewPageForPDT);
			pdpe[PDPE(va)] = 0;
			return NULL;
		}
		return pte;
	}
	else
		// @@@ pdpe doesn't exist and create == false
		return NULL;
}

// Given 'pgdir', a pointer to a page directory, pgdir_walk returns
// a pointer to the page table entry (PTE). 
// The programming logic and the hints are the same as pml4e_walk
// and pdpe_walk.

pte_t *
pgdir_walk(pde_t *pgdir, const void *va, int create)
{
	// Fill this function in
	pte_t *pte = NULL;
	
	// @@@ if pdpe exist, simply call pgdir_walk()
	if((pgdir[PDX(va)] & PTE_P))
	{
		pte = (pte_t*)KADDR((PTE_ADDR(pgdir[PDX(va)]) & ~0xFFF) + PTX(va)*8);
		#ifdef DEBUG
		cprintf("pgdir_walk: &pgdir[PDX(va)]: %x pgdir[PDX(va)]: %x\n", &pgdir[PDX(va)], pgdir[PDX(va)]);
		cprintf("pgdir_walk: pte: %x, *pte %x \n" , pte, *pte);
		#endif
		return pte;
	}
	else if(create == true)
	{
		struct PageInfo* NewPageForPT = page_alloc(ALLOC_ZERO);
		if (NewPageForPT == NULL)
			return NULL;
		NewPageForPT->pp_ref++;	// reference ctr incremented by 1
		// Assigned new page to *pdpe
		pgdir[PDX(va)] = (page2pa(NewPageForPT) & ~0xFFF) | PTE_USER;
		pte = (pte_t*)KADDR((PTE_ADDR(pgdir[PDX(va)]) & ~0xFFF) + PTX(va)*8);
		#ifdef DEBUG
		cprintf("pgdir_walk: &pgdir[PDX(va)]: %x pgdir[PDX(va)]: %x\n", &pgdir[PDX(va)], pgdir[PDX(va)]);
		cprintf("pgdir_walk: pte: %x, *pte %x \n" , pte, *pte);
		#endif
		if(pte == NULL) 
		{
			NewPageForPT->pp_ref--;
			page_free(NewPageForPT);
			pgdir[PDX(va)] = 0;
			return NULL;
		}
		return pte;
	}
	else
		// @@@ pgdir doesn't exist and create == false
		return NULL;
}

//
// Map [va, va+size) of virtual address space to physical [pa, pa+size)
// in the page table rooted at pml4e.  Size is a multiple of PGSIZE.
// Use permission bits perm|PTE_P for the entries.							// @@@ here might be wrong
//
// This function is only intended to set up the "static" mappings
// above UTOP. As such, it should *not* change the pp_ref field on the
// mapped pages.
//
// Hint: the TA solution uses pml4e_walk
	static void
boot_map_region(pml4e_t *pml4e, uintptr_t la, size_t size, physaddr_t pa, int perm)
{
	// Fill this function in
	uintptr_t top = ROUNDUP(la+size, PGSIZE);
	char *va_temp, *pa_temp;
	for(va_temp = (char*)la, pa_temp = (char*)pa; (uintptr_t)va_temp < top; va_temp+=PGSIZE, pa_temp+=PGSIZE)
	{
		pte_t *pte = pml4e_walk(pml4e, (char*)va_temp, 1);
		*pte = (uintptr_t)pa_temp | perm | PTE_P;
	}
	cprintf("boot_map_region: map [%x, %x) to [%x, %x) success!\n", la, la+size, pa, pa+size);
}

//
// Map the physical page 'pp' at virtual address 'va'.
// The permissions (the low 12 bits) of the page table entry
// should be set to 'perm|PTE_P'.
//
// Requirements
//   - If there is already a page mapped at 'va', it should be page_remove()d.
//   - If necessary, on demand, a page table should be allocated and inserted
//     into 'pml4e through pdpe through pgdir'.
//   - pp->pp_ref should be incremented if the insertion succeeds.
//   - The TLB must be invalidated if a page was formerly present at 'va'.
//
// Corner-case hint: Make sure to consider what happens when the same
// pp is re-inserted at the same virtual address in the same pgdir.
// However, try not to distinguish this case in your code, as this
// frequently leads to subtle bugs; there's an elegant way to handle
// everything in one code path.
//
// RETURNS:
//   0 on success
//   -E_NO_MEM, if page table couldn't be allocated
//
// Hint: The TA solution is implemented using pml4e_walk, page_remove,
// and page2pa.
//
int
page_insert(pml4e_t *pml4e, struct PageInfo *pp, void *va, int perm)
{
	// Fill this function in
	pte_t *pte = pml4e_walk(pml4e, va, 1);
	if (pte == NULL)
		return -E_NO_MEM;
	if (*pte & PTE_P)
	{
		page_remove(pml4e, va);
	}
	pp->pp_ref++;
	*pte = (page2pa(pp) & ~0xFFF) | (perm|PTE_P);
	#ifdef DEBUG
	cprintf("page_insert: pte %x, *pte: %x\n", pte, *pte);
	#endif
	
	return 0;
}

//
// Return the page mapped at virtual address 'va'.
// If pte_store is not zero, then we store in it the address
// of the pte for this page.  This is used by page_remove and
// can be used to verify page permissions for syscall arguments,
// but should not be used by most callers.
//
// Return NULL if there is no page mapped at va.
//
// Hint: the TA solution uses pml4e_walk and pa2page.
//
struct PageInfo *
page_lookup(pml4e_t *pml4e, void *va, pte_t **pte_store)
{
	// Fill this function in
	struct PageInfo *result;
	pte_t *pte = pml4e_walk(pml4e, va, 0);
	if(pte == NULL) {
		return NULL;
	}
	physaddr_t pa = (physaddr_t)((*pte & ~0xFFF) + PGOFF(va));
	result = pa2page(pa);
	if(pte_store != NULL)
		*pte_store = pte;
	return result;
}

//
// Unmaps the physical page at virtual address 'va'.
// If there is no physical page at that address, silently does nothing.
//
// Details:
//   - The ref count on the physical page should decrement.
//   - The physical page should be freed if the ref count reaches 0.
//   - The page table entry corresponding to 'va' should be set to 0.
//     (if such a PTE exists)
//   - The TLB must be invalidated if you remove an entry from
//     the page table.
//
// Hint: The TA solution is implemented using page_lookup,
// 	tlb_invalidate, and page_decref.
//
void
page_remove(pml4e_t *pml4e, void *va)
{
	// Fill this function in
	struct PageInfo *PageToBeRemoved = page_lookup(pml4e, va, 0);
	if(PageToBeRemoved != NULL)
	{
		page_decref(PageToBeRemoved);
		pte_t *pte = pml4e_walk(pml4e, va, 0);
		if (pte != NULL)
			*pte = 0;
		tlb_invalidate(pml4e, va);
	}
}

//
// Invalidate a TLB entry, but only if the page tables being
// edited are the ones currently in use by the processor.
//
	void
tlb_invalidate(pml4e_t *pml4e, void *va)
{
	// Flush the entry only if we're modifying the current address space.
	// For now, there is only one address space, so always invalidate.
	invlpg(va);
}

static uintptr_t user_mem_check_addr;

//
// Check that an environment is allowed to access the range of memory
// [va, va+len) with permissions 'perm | PTE_P'.
// Normally 'perm' will contain PTE_U at least, but this is not required.
// 'va' and 'len' need not be page-aligned; you must test every page that
// contains any of that range.  You will test either 'len/PGSIZE',
// 'len/PGSIZE + 1', or 'len/PGSIZE + 2' pages.
//
// A user program can access a virtual address if (1) the address is below
// ULIM, and (2) the page table gives it permission.  These are exactly
// the tests you should implement here.
//
// If there is an error, set the 'user_mem_check_addr' variable to the first
// erroneous virtual address.
//
// Returns 0 if the user program can access this range of addresses,
// and -E_FAULT otherwise.
//
	int
user_mem_check(struct Env *env, const void *va, size_t len, int perm)
{
	// LAB 3: Your code here.
	return 0;

}

//
// Checks that environment 'env' is allowed to access the range
// of memory [va, va+len) with permissions 'perm | PTE_U | PTE_P'.
// If it can, then the function simply returns.
// If it cannot, 'env' is destroyed and, if env is the current
// environment, this function will not return.
//
	void
user_mem_assert(struct Env *env, const void *va, size_t len, int perm)
{
	if (user_mem_check(env, va, len, perm | PTE_U) < 0) {
		cprintf("[%08x] user_mem_check assertion failure for "
			"va %08x\n", env->env_id, user_mem_check_addr);
		env_destroy(env);	// may not return
	}
}


// --------------------------------------------------------------
// Checking functions.
// --------------------------------------------------------------

//
// Check that the pages on the page_free_list are reasonable.
//

static void
check_page_free_list(bool only_low_memory)
{
	struct PageInfo *pp;
	unsigned pdx_limit = only_low_memory ? 1 : NPDENTRIES;
	uint64_t nfree_basemem = 0, nfree_extmem = 0;
	char *first_free_page;

	if (!page_free_list)
		panic("'page_free_list' is a null pointer!");

	if (only_low_memory) {
		// Move pages with lower addresses first in the free
		// list, since entry_pgdir does not map all pages.
		struct PageInfo *pp1, *pp2;
		struct PageInfo **tp[2] = { &pp1, &pp2 };
		for (pp = page_free_list; pp; pp = pp->pp_link) {
			int pagetype = PDX(page2pa(pp)) >= pdx_limit;
			*tp[pagetype] = pp;
			tp[pagetype] = &pp->pp_link;
		}
		*tp[1] = 0;
		*tp[0] = pp2;
		page_free_list = pp1;
	}

	// if there's a page that shouldn't be on the free list,
	// try to make sure it eventually causes trouble.
	for (pp = page_free_list; pp; pp = pp->pp_link)
		if (PDX(page2pa(pp)) < pdx_limit)
			memset(page2kva(pp), 0x97, 128);

	first_free_page = (char *) boot_alloc(0);
	for (pp = page_free_list; pp; pp = pp->pp_link) {
		// check that we didn't corrupt the free list itself
		assert(pp >= pages);
		assert(pp < pages + npages);
		assert(((char *) pp - (char *) pages) % sizeof(*pp) == 0);

		// check a few pages that shouldn't be on the free list
		assert(page2pa(pp) != 0);
		assert(page2pa(pp) != IOPHYSMEM);
		assert(page2pa(pp) != EXTPHYSMEM - PGSIZE);
		assert(page2pa(pp) != EXTPHYSMEM);
		assert(page2pa(pp) < EXTPHYSMEM || (char *) page2kva(pp) >= first_free_page);

		if (page2pa(pp) < EXTPHYSMEM)
			++nfree_basemem;
		else
			++nfree_extmem;
	}

	assert(nfree_extmem > 0);
	#ifdef DEBUG
	cprintf("[DEBUG] check_page_free_list(): check page free memory passed!\n");
	#endif
}


//
// Check the physical page allocator (page_alloc(), page_free(),
// and page_init()).
//
static void
check_page_alloc(void)
{
	struct PageInfo *pp, *pp0, *pp1, *pp2;
	int nfree;
	struct PageInfo *fl;
	char *c;
	int i;

	// if there's a page that shouldn't be on
	// the free list, try to make sure it
	// eventually causes trouble.
	
	for (pp0 = page_free_list, nfree = 0; pp0; pp0 = pp0->pp_link) {
		#ifdef DEBUG
		if ((uint64_t)pp0==0x800432fff0 || (uint64_t)pp0==0x8004330000)
		{
			//cprintf("[DEBUG] pp0\t%08x (pointer addr) %08x %08x (page kva)\n", pp0, pp0->pp_link, (uintptr_t)page2kva(pp0));
		}
		#endif
		memset(page2kva(pp0), 0x97, PGSIZE);
	}
	
	#ifdef DEBUG
	cprintf("[DEBUG] Check free page finished!\n");
	#endif
	
	for (pp0 = page_free_list, nfree = 0; pp0; pp0 = pp0->pp_link) {
		// check that we didn't corrupt the free list itself
		assert(pp0 >= pages);
		assert(pp0 < pages + npages);

		// check a few pages that shouldn't be on the free list
		assert(page2pa(pp0) != 0);
		assert(page2pa(pp0) != IOPHYSMEM);
		assert(page2pa(pp0) != EXTPHYSMEM - PGSIZE);
		assert(page2pa(pp0) != EXTPHYSMEM);
	}
	// should be able to allocate three pages
	pp0 = pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));
	assert(pp0);
	assert(pp1 && pp1 != pp0);
	assert(pp2 && pp2 != pp1 && pp2 != pp0);
	assert(page2pa(pp0) < npages*PGSIZE);
	assert(page2pa(pp1) < npages*PGSIZE);
	assert(page2pa(pp2) < npages*PGSIZE);

	// temporarily steal the rest of the free pages
	fl = page_free_list;
	page_free_list = 0;

	// should be no free memory
	assert(!page_alloc(0));

	// free and re-allocate?
	page_free(pp0);
	page_free(pp1);
	page_free(pp2);
	pp0 = pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));
	assert(pp0);
	assert(pp1 && pp1 != pp0);
	assert(pp2 && pp2 != pp1 && pp2 != pp0);
	assert(!page_alloc(0));

	// test flags
	memset(page2kva(pp0), 1, PGSIZE);
	page_free(pp0);
	assert((pp = page_alloc(ALLOC_ZERO)));
	assert(pp && pp0 == pp);
	c = page2kva(pp);
	for (i = 0; i < PGSIZE; i++)
		assert(c[i] == 0);

	// give free list back
	page_free_list = fl;

	// free the pages we took
	page_free(pp0);
	page_free(pp1);
	page_free(pp2);

	cprintf("check_page_alloc() succeeded!\n");
}

//
// Checks that the kernel part of virtual address space
// has been setup roughly correctly (by mem_init()).
//
// This function doesn't test every corner case,
// but it is a pretty good sanity check.
//

static void
check_boot_pml4e(pml4e_t *pml4e)
{
	uint64_t i, n;

	pml4e = boot_pml4e;

	// check pages array
	n = ROUNDUP(npages*sizeof(struct PageInfo), PGSIZE);
	for (i = 0; i < n; i += PGSIZE) {
		//cprintf("%x %x %x\n",i,check_va2pa(pml4e, UPAGES + i), PADDR(pages) + i);
		assert(check_va2pa(pml4e, UPAGES + i) == PADDR(pages) + i);
	}

	// check envs array (new test for lab 3)
	n = ROUNDUP(NENV*sizeof(struct Env), PGSIZE);
	for (i = 0; i < n; i += PGSIZE)
		assert(check_va2pa(pml4e, UENVS + i) == PADDR(envs) + i);

	// check phys mem
	for (i = 0; i < npages * PGSIZE; i += PGSIZE)
		assert(check_va2pa(pml4e, KERNBASE + i) == i);

	// check kernel stack
	for (i = 0; i < KSTKSIZE; i += PGSIZE) {
		assert(check_va2pa(pml4e, KSTACKTOP - KSTKSIZE + i) == PADDR(bootstack) + i);
    }
	assert(check_va2pa(pml4e, KSTACKTOP - KSTKSIZE - 1 )  == ~0);

	pdpe_t *pdpe = KADDR(PTE_ADDR(boot_pml4e[1]));
	pde_t  *pgdir = KADDR(PTE_ADDR(pdpe[0]));
	// check PDE permissions
	for (i = 0; i < NPDENTRIES; i++) {
		switch (i) {
			//case PDX(UVPT):
			case PDX(KSTACKTOP - 1):
			case PDX(UPAGES):
			case PDX(UENVS):
				assert(pgdir[i] & PTE_P);
				break;
			default:
				if (i >= PDX(KERNBASE)) {
					if (pgdir[i] & PTE_P)
                        assert(pgdir[i] & PTE_W);
                    else
                        assert(pgdir[i] == 0);
				} 
				break;
		}
	}
	cprintf("check_boot_pml4e() succeeded!\n");
}

// This function returns the physical address of the page containing 'va',
// defined by the 'pml4e'.  The hardware normally performs
// this functionality for us!  We define our own version to help check
// the check_boot_pml4e() function; it shouldn't be used elsewhere.

	static physaddr_t
check_va2pa(pml4e_t *pml4e, uintptr_t va)
{
	pte_t *pte;
	pdpe_t *pdpe;
	pde_t *pde;
	// cprintf("va: %x\n", va);
	
	pml4e = &pml4e[PML4(va)];
	// cprintf("check_va2pa: PML4(va) %x *pml4e %x\n" , PML4(va), *pml4e);
	if(!(*pml4e & PTE_P))
		return ~0;
		
	pdpe = (pdpe_t *) KADDR(PTE_ADDR(*pml4e));
	// cprintf("check_va2pa: pdpe %x *pdpe %x\n" , pdpe, *pdpe);
	if (!(pdpe[PDPE(va)] & PTE_P))
		return ~0;
		
	pde = (pde_t *) KADDR(PTE_ADDR(pdpe[PDPE(va)]));
	// cprintf("check_va2pa: pde %x *pde %x\n" , pde, *pde);
	pde = &pde[PDX(va)];
	if (!(*pde & PTE_P))
		return ~0;
		
	pte = (pte_t*) KADDR(PTE_ADDR(*pde));
	// cprintf("check_va2pa: pte %x *pte %x\n" , pte, *pte);
	if (!(pte[PTX(va)] & PTE_P)) {
		// cprintf("check_va2pa: PTX(va) %x &pte[PTX(va)]: %x, pte[PTX(va)]: %x\n", PTX(va), &pte[PTX(va)], pte[PTX(va)]);
		return ~0;
	}
	// cprintf("check_va2pa: PTX(va) %x PTE_ADDR(pte[PTX(va)]) %x\n" , PTX(va),  PTE_ADDR(pte[PTX(va)]));
	
	return PTE_ADDR(pte[PTX(va)]);
}


// check page_insert, page_remove, &c
static void
page_check(void)
{
	struct PageInfo *pp0, *pp1, *pp2,*pp3,*pp4,*pp5;
	struct PageInfo * fl;
	pte_t *ptep, *ptep1;
	pdpe_t *pdpe;
	pde_t *pde;
	void *va;
	int i;
	pp0 = pp1 = pp2 = pp3 = pp4 = pp5 =0;
	assert(pp0 = page_alloc(0));
	assert(pp1 = page_alloc(0));
	assert(pp2 = page_alloc(0));
	assert(pp3 = page_alloc(0));
	assert(pp4 = page_alloc(0));
	assert(pp5 = page_alloc(0));

	assert(pp0);
	assert(pp1 && pp1 != pp0);
	assert(pp2 && pp2 != pp1 && pp2 != pp0);
	assert(pp3 && pp3 != pp2 && pp3 != pp1 && pp3 != pp0);
	assert(pp4 && pp4 != pp3 && pp4 != pp2 && pp4 != pp1 && pp4 != pp0);
	assert(pp5 && pp5 != pp4 && pp5 != pp3 && pp5 != pp2 && pp5 != pp1 && pp5 != pp0);

	// temporarily steal the rest of the free pages
	fl = page_free_list;
	page_free_list = NULL;		// @@@ no free page from here!

	// should be no free memory
	assert(!page_alloc(0));

	// there is no page allocated at address 0
	assert(page_lookup(boot_pml4e, (void *) 0x0, &ptep) == NULL);

	// there is no free memory, so we can't allocate a page table 
	assert(page_insert(boot_pml4e, pp1, 0x0, 0) < 0);

	// free pp0 and try again: pp0 should be used for page table
	page_free(pp0);
	assert(page_insert(boot_pml4e, pp1, 0x0, 0) < 0);
	page_free(pp2);
	page_free(pp3);
	//cprintf("pp1 ref count = %d\n",pp1->pp_ref);
	//cprintf("pp0 ref count = %d\n",pp0->pp_ref);
	//cprintf("pp2 ref count = %d\n",pp2->pp_ref);
	assert(page_insert(boot_pml4e, pp1, 0x0, 0) == 0);
	assert((PTE_ADDR(boot_pml4e[0]) == page2pa(pp0) || PTE_ADDR(boot_pml4e[0]) == page2pa(pp2) || PTE_ADDR(boot_pml4e[0]) == page2pa(pp3) ));
	assert(check_va2pa(boot_pml4e, 0x0) == page2pa(pp1));
	assert(pp1->pp_ref == 1);
	assert(pp0->pp_ref == 1);
	assert(pp2->pp_ref == 1);
	//should be able to map pp3 at PGSIZE because pp0 is already allocated for page table
	assert(page_insert(boot_pml4e, pp3, (void*) PGSIZE, 0) == 0);
	//cprintf("page_check: (void*) PGSIZE: %x\n", (void*) PGSIZE);
	//cprintf("page_check: check_va2pa(boot_pml4e, PGSIZE) %x, page2pa(pp3) %x\n", check_va2pa(boot_pml4e, PGSIZE), page2pa(pp3));
	assert(check_va2pa(boot_pml4e, PGSIZE) == page2pa(pp3));
	assert(pp3->pp_ref == 2);

	// should be no free memory
	assert(!page_alloc(0));

	// should be able to map pp3 at PGSIZE because it's already there
	assert(page_insert(boot_pml4e, pp3, (void*) PGSIZE, 0) == 0);
	assert(check_va2pa(boot_pml4e, PGSIZE) == page2pa(pp3));
	assert(pp3->pp_ref == 2);

	// pp3 should NOT be on the free list
	// could happen in ref counts are handled sloppily in page_insert
	assert(!page_alloc(0));
	// check that pgdir_walk returns a pointer to the pte
	pdpe = KADDR(PTE_ADDR(boot_pml4e[PML4(PGSIZE)]));
	pde = KADDR(PTE_ADDR(pdpe[PDPE(PGSIZE)]));
	ptep = KADDR(PTE_ADDR(pde[PDX(PGSIZE)]));
	assert(pml4e_walk(boot_pml4e, (void*)PGSIZE, 0) == ptep+PTX(PGSIZE));

	// should be able to change permissions too.
	assert(page_insert(boot_pml4e, pp3, (void*) PGSIZE, PTE_U) == 0);
	assert(check_va2pa(boot_pml4e, PGSIZE) == page2pa(pp3));
	assert(pp3->pp_ref == 2);
	assert(*pml4e_walk(boot_pml4e, (void*) PGSIZE, 0) & PTE_U);
	assert(boot_pml4e[0] & PTE_U);


	// should not be able to map at PTSIZE because need free page for page table
	assert(page_insert(boot_pml4e, pp0, (void*) PTSIZE, 0) < 0);

	// insert pp1 at PGSIZE (replacing pp3)
	assert(page_insert(boot_pml4e, pp1, (void*) PGSIZE, 0) == 0);
	assert(!(*pml4e_walk(boot_pml4e, (void*) PGSIZE, 0) & PTE_U));

	// should have pp1 at both 0 and PGSIZE
	assert(check_va2pa(boot_pml4e, 0) == page2pa(pp1));
	assert(check_va2pa(boot_pml4e, PGSIZE) == page2pa(pp1));
	// ... and ref counts should reflect this
	assert(pp1->pp_ref == 2);
	assert(pp3->pp_ref == 1);


	// unmapping pp1 at 0 should keep pp1 at PGSIZE
	page_remove(boot_pml4e, 0x0);
	assert(check_va2pa(boot_pml4e, 0x0) == ~0);
	assert(check_va2pa(boot_pml4e, PGSIZE) == page2pa(pp1));
	assert(pp1->pp_ref == 1);
	assert(pp3->pp_ref == 1);

	// Test re-inserting pp1 at PGSIZE.
	// Thanks to Varun Agrawal for suggesting this test case.
	assert(page_insert(boot_pml4e, pp1, (void*) PGSIZE, 0) == 0);
	assert(pp1->pp_ref);
	assert(pp1->pp_link == NULL);

	// unmapping pp1 at PGSIZE should free it
	page_remove(boot_pml4e, (void*) PGSIZE);
	assert(check_va2pa(boot_pml4e, 0x0) == ~0);
	assert(check_va2pa(boot_pml4e, PGSIZE) == ~0);
	assert(pp1->pp_ref == 0);
	assert(pp3->pp_ref == 1);


#if 0
	// should be able to page_insert to change a page
	// and see the new data immediately.
	memset(page2kva(pp1), 1, PGSIZE);
	memset(page2kva(pp2), 2, PGSIZE);
	page_insert(boot_pgdir, pp1, 0x0, 0);
	assert(pp1->pp_ref == 1);
	assert(*(int*)0 == 0x01010101);
	page_insert(boot_pgdir, pp2, 0x0, 0);
	assert(*(int*)0 == 0x02020202);
	assert(pp2->pp_ref == 1);
	assert(pp1->pp_ref == 0);
	page_remove(boot_pgdir, 0x0);
	assert(pp2->pp_ref == 0);
#endif

	// forcibly take pp3 back
	assert(PTE_ADDR(boot_pml4e[0]) == page2pa(pp3));
	boot_pml4e[0] = 0;
	assert(pp3->pp_ref == 1);
    page_decref(pp3);
	// check pointer arithmetic in pml4e_walk
	page_decref(pp0);
	page_decref(pp2);
	va = (void*)(PGSIZE * 100);
	ptep = pml4e_walk(boot_pml4e, va, 1);
	pdpe = KADDR(PTE_ADDR(boot_pml4e[PML4(va)]));
	pde  = KADDR(PTE_ADDR(pdpe[PDPE(va)]));
	ptep1 = KADDR(PTE_ADDR(pde[PDX(va)]));
	assert(ptep == ptep1 + PTX(va));
	
    // check that new page tables get cleared
    page_decref(pp4);
	memset(page2kva(pp4), 0xFF, PGSIZE);
	pml4e_walk(boot_pml4e, 0x0, 1);
	pdpe = KADDR(PTE_ADDR(boot_pml4e[0]));
    pde  = KADDR(PTE_ADDR(pdpe[0]));
    ptep  = KADDR(PTE_ADDR(pde[0]));
	for(i=0; i<NPTENTRIES; i++)
		assert((ptep[i] & PTE_P) == 0);
	boot_pml4e[0] = 0;

	// give free list back
	page_free_list = fl;

	// free the pages we took
	page_decref(pp0);
	page_decref(pp1);
	page_decref(pp2);

	cprintf("check_page() succeeded!\n");
}

