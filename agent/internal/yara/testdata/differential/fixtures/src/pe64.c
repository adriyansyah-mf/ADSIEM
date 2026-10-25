// Small x64 PE: a few kernel32/user32 imports, no CRT.
#include <windows.h>

void start(void) {
	char buf[64];
	DWORD t = GetTickCount();
	wsprintfA(buf, "tick %lu", t);
	if (t == 0) {
		MessageBoxA(NULL, buf, "pe64 fixture", MB_OK);
	}
	Sleep(1);
	ExitProcess(t & 1);
}
