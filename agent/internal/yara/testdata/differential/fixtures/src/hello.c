// Dynamically linked ELF with a symbol table and a dynamic section.
#include <stdio.h>

int fixture_global = 42;

int fixture_function(int x) { return x * fixture_global; }

int main(void) {
	printf("hello %d\n", fixture_function(2));
	return 0;
}
