// Punch a module into the kernel with brute force.
// This code assumes that you have total trust into the
// module file because you're about to load it into the
// kernel, so it doesn't protect against maliciously
// crafted or broken ELFs.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/klog.h>
#include <string.h>
#include <elf.h>

#define VERMAGIC_NEEDLE_1 ": version magic '"
#define VERMAGIC_NEEDLE_2 "' should be '"

#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr

// WTF is up with the init_module(2) manpage? two args, and one of them
// is a totally weird struct? gah.
extern long init_module(void *, unsigned long, const char *);

/* Find a module section: 0 means not found. */
static unsigned int find_sec(Elf_Ehdr *hdr, Elf_Shdr *sechdrs, char *secstrings, const char *name) {
	unsigned int i;

	for (i = 1; i < hdr->e_shnum; i++) {
		Elf_Shdr *shdr = &sechdrs[i];
		/* Alloc bit cleared means "ignore it." */
		if ((shdr->sh_flags & SHF_ALLOC)
		    && strcmp(secstrings + shdr->sh_name, name) == 0)
			return i;
	}
	return 0;
}

static int punch(void *data, off_t *orig_len, char *new_vermagic) {
  Elf_Ehdr *hdr = data;
  
  // find .modinfo section
  Elf_Shdr *sechdrs = (void *)hdr + hdr->e_shoff;
	char *secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;
	unsigned int modinfo_sec_i = find_sec(hdr, sechdrs, secstrings, ".modinfo");
	if (modinfo_sec_i == 0) return 1;
	Elf_Shdr *modinfo_sec_hdr = &sechdrs[modinfo_sec_i];
	char *modinfo_text = data + modinfo_sec_hdr->sh_offset;
	
	// clone section
	int modinfo_len = modinfo_sec_hdr->sh_size;
	char *new_modinfo = data + *orig_len; /* just append to the end of the elf file */
	char *new_modinfo_end = new_modinfo + modinfo_len;
	memcpy(new_modinfo, modinfo_text, modinfo_len);
	
	// wipe old vermagic
	char *modinfo_vermagic;
	if (memcmp(new_modinfo, "vermagic=", 9) == 0) {
	  modinfo_vermagic = new_modinfo;
	} else {
	  modinfo_vermagic = memmem(new_modinfo, modinfo_len, "\0vermagic=", 10)+1;
	}
	if (modinfo_vermagic != NULL+1) {
	  int vermagic_len = strlen(modinfo_vermagic)+1;
	  printf("deleting %i bytes of old vermagic ('%s') from copied modinfo section\n", vermagic_len, modinfo_vermagic);
	  char *vermagic_end = modinfo_vermagic+vermagic_len;
	  memmove(modinfo_vermagic, vermagic_end, new_modinfo_end - vermagic_end);
	  modinfo_len -= vermagic_len;
	  new_modinfo_end -= vermagic_len;
	} else {
	  printf("warning: no old modinfo found!\n");
	}
	
	// append new vermagic
	strcpy(new_modinfo_end, "vermagic=");
	strcpy(new_modinfo_end+9, new_vermagic);
	modinfo_len += 9+strlen(new_vermagic)+1;
	
	// update pointer for new section
	modinfo_sec_hdr->sh_offset = *orig_len;
	modinfo_sec_hdr->sh_size = modinfo_len;
	*orig_len += modinfo_len;
	
	// At this point, I thought: "Oh damn, what do I do about sh_addr? How can I find
	// a free memory location? Oh nooooes!!!"
	// Turns out the first thing the kernel does with that field is to overwrite it. :/
	modinfo_sec_hdr->sh_addr = 0; // crash if I'm wrong
	
	return 0;
}

int extract_vermagic(char *buf, size_t len, char **result, size_t *result_len) {
  char *ptr = buf, *end = buf+len;
  while (1) {
    char *lineend = memchr(ptr, '\0', end-ptr);
    if (lineend == NULL) break;
    char *needle1_pos = memmem(ptr, lineend-ptr, VERMAGIC_NEEDLE_1, strlen(VERMAGIC_NEEDLE_1));
    if (needle1_pos == NULL) goto next;
    char *needle2_pos = memmem(needle1_pos, lineend-needle1_pos, VERMAGIC_NEEDLE_2, strlen(VERMAGIC_NEEDLE_2));
    if (needle2_pos == NULL) goto next;
    // wheee, found it!
    *result = needle2_pos + strlen(VERMAGIC_NEEDLE_2);
    char *vermagic_end = strchr(*result, '\'');
    if (vermagic_end == NULL) goto next;
    *result_len = vermagic_end - *result;
    return 0;
next:
    ptr = lineend+1;
  }
  return 1;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("call with two args (path, options [yes, as one argument!]), please!\n");
    exit(1);
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    printf("can't open file: %s\n", strerror(errno));
    exit(1);
  }
  
  struct stat st;
  if (fstat(fd, &st)) {
    printf("can't stat opened file: %s\n", strerror(errno));
    exit(1);
  }
  
  void *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
  if (!init_module(data, st.st_size, argv[2])) {
    // whoah, everything went fine? exact vermagic match,
    // no need to punch? :( - I want to punch!
    exit(0);
  }
  
  if (errno != ENOEXEC) {
    printf("init_module syscall failed with error (might be VERY misleading): %s\n", strerror(errno));
    exit(1);
  }
  
  // we'll just guess it's because of a vermagic mismatch for now.
  printf("no luck the friendly way, going to try it with a punch...\n");
  // extract needed vermagic
  char dmesg_buf[10001];
  klogctl(3, dmesg_buf, sizeof(dmesg_buf)-1);
  char *needed_vermagic;
  size_t vermagic_length;
  if (extract_vermagic(dmesg_buf, sizeof(dmesg_buf), &needed_vermagic, &vermagic_length)) {
    printf("module loading attempt failed with ENOEXEC and there's no vermagic mismatch in the syslog; aborting.\n");
    exit(1);
  }
  needed_vermagic[vermagic_length] = '\0';
  printf("needed vermagic: %s\n", needed_vermagic);
  
  // hairy part: fix the vermagic!
  char *old_data = data;
  data = malloc(st.st_size + 1024 /* just assume modinfo is smaller than this */);
  memcpy(data, old_data, st.st_size);
  munmap(old_data, st.st_size);
  if (punch(data, &st.st_size, needed_vermagic)) {
    printf("internal punching failure - did you supply a valid ELF?\n");
    exit(1);
  }
  
  // debug code
  /*
  int outfd = open("/tmp/punchdebug.ko", O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
  write(outfd, data, st.st_size);
  close(outfd);
  */
  
  // now try loading this
  if (init_module(data, st.st_size, argv[2])) {
    printf("init_module syscall failed with error (might be VERY misleading): %s\n", strerror(errno));
    return 1;
  } else {
    printf("successfully punched the small bitblob into almighty bitblob! :)\n");
    return 0;
  }
}
