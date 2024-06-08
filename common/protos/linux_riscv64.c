#if defined(__riscv64)

#include <stdint.h>
#include <stddef.h>
#include <stdnoreturn.h>
#include <protos/linux.h>
#include <fs/file.h>
#include <lib/libc.h>
#include <lib/misc.h>
#include <lib/real.h>
#include <lib/term.h>
#include <lib/config.h>
#include <lib/print.h>
#include <lib/uri.h>
#include <mm/pmm.h>
#include <sys/idt.h>
#include <lib/fb.h>
#include <lib/acpi.h>
#include <drivers/edid.h>
#include <drivers/vga_textmode.h>
#include <drivers/gop.h>

// The following definitions and struct were copied and adapted from Linux
// kernel headers released under GPL-2.0 WITH Linux-syscall-note
// allowing their inclusion in non GPL compliant code.

struct linux_header {
	uint32_t code0;
	uint32_t code1;
	uint64_t text_offset;
	uint64_t image_size;
	uint64_t flags;
	uint32_t version;
	uint32_t res1;
	uint64_t res2;
	uint64_t res3;		// originally 'magic' field, deprecated
	uint32_t magic2;
	uint32_t res4;
} __attribute__((packed));

#define LINUX_HEADER_MAGIC2		0x05435352
#define LINUX_HEADER_MAJOR_VER(ver)	(((ver) >> 16)  & 0xffff)
#define LINUX_HEADER_MINOR_VER(ver)	(((ver) >> 0) & 0xffff)

// End of Linux code

noreturn void linux_spinup(uint64_t hartid, void *dtb, void *entry);

noreturn void linux_load(char *config, char *cmdline) {
    struct file_handle *kernel_file;

    char *kernel_path = config_get_value(config, 0, "KERNEL_PATH");
    if (kernel_path == NULL)
        panic(true, "linux: KERNEL_PATH not specified");

    print("linux: Loading kernel `%#`...\n", kernel_path);

    if ((kernel_file = uri_open(kernel_path)) == NULL)
        panic(true, "linux: Failed to open kernel with path `%#`. Is the path correct?", kernel_path);

    struct linux_header header;
    fread(kernel_file, &header, 0, sizeof(header));

    if (header.magic2 != LINUX_HEADER_MAGIC2) {
        panic(true, "kernel header magic not match");
    }

    printv("kernel version %d.%d\n", LINUX_HEADER_MAJOR_VER(header.version),
    				     LINUX_HEADER_MINOR_VER(header.version));
    if (LINUX_HEADER_MINOR_VER(header.version) < 2) {
        panic(true, "protocols < 0.2 are not supported");
    }

    printv("image size: %d %x\n", header.image_size, header.image_size);

    void *base = ext_mem_alloc_type_aligned(
    		ALIGN_UP(kernel_file->size, 4096),
		MEMMAP_USABLE, 2 * 1024 * 1024);
    fread(kernel_file, base, 0, kernel_file->size);
    fclose(kernel_file);

    void *dtb = get_device_tree_blob();
    if (!dtb)
        panic(true, "no device tree blob found");

    printv("kernel load address: %x\n", base);
    printv("bps hart = %d, device tree blob at %x\n", bsp_hartid, dtb);

    linux_spinup(bsp_hartid, get_device_tr, base);
}

#endif	// __riscv64
