#ifndef JOS_INC_ELF_H
#define JOS_INC_ELF_H

#define ELF_MAGIC 0x464C457FU	/* "\x7FELF" in little endian */

struct Elf {
	uint32_t e_magic;	// must equal ELF_MAGIC
	uint8_t e_elf[12];	// @@@ Not important. Don't care
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;	// @@@ va of program start, important
	uint64_t e_phoff;	// @@@ program header offset
	uint64_t e_shoff;	// @@@ section header offset
	uint32_t e_flags;	// @@@ stores the value of flags register for this elf
	uint16_t e_ehsize;	// @@@ elf header's size
	uint16_t e_phentsize;	// @@@ size of one entry in program header table
	uint16_t e_phnum;	// @@@ number of program header table entries
	uint16_t e_shentsize;	// @@@ size of one entry in section header table
	uint16_t e_shnum;	// @@@ number of section header table entries
	uint16_t e_shstrndx;	// @@@ offset of string table entry in section header table (could be SHN_UNDEF)
};

struct Proghdr {
	uint32_t p_type;
    uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_va;
	uint64_t p_pa;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

struct Secthdr {
	uint32_t sh_name;	// @@@ e.g. .text .date .stack .debuginfo .rodata .bss
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;	// @@@ virtual address for each section
	uint64_t sh_offset;	// @@@ offset from beginning of file to the section this entry points to
	uint64_t sh_size;	// @@@ size of the secion
	uint32_t sh_link;	// @@@ Figure 1-12
	uint32_t sh_info;	// @@@ Figure 1-12
	uint64_t sh_addralign;	// @@@ specify the alignment requirement
	uint64_t sh_entsize;	// @@@ entry size of the table this section holds. Mostly zeor (means no table)
};


// Values for Proghdr::p_type
#define ELF_PROG_LOAD		1

// Flag bits for Proghdr::p_flags
#define ELF_PROG_FLAG_EXEC	1
#define ELF_PROG_FLAG_WRITE	2
#define ELF_PROG_FLAG_READ	4

// Values for Secthdr::sh_type
#define ELF_SHT_NULL		0
#define ELF_SHT_PROGBITS	1
#define ELF_SHT_SYMTAB		2
#define ELF_SHT_STRTAB		3

// Values for Secthdr::sh_name
#define ELF_SHN_UNDEF		0

#endif /* !JOS_INC_ELF_H */
