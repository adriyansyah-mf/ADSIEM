// Tiny freestanding ELF: exits through a raw syscall.
static const char marker[] = "elf fixture marker";

void _start(void) {
	long n = sizeof(marker);
	__asm__ volatile("mov $60, %%eax\n\tmov %0, %%rdi\n\tsyscall" : : "r"(n) : "rax", "rdi");
	for (;;) {
	}
}
