// Small x86 DLL with named exports, one ordinal-only import.
#include <windows.h>

__declspec(dllexport) int FixtureAdd(int a, int b) { return a + b; }
__declspec(dllexport) int FixtureMul(int a, int b) { return a * b; }
__declspec(dllexport) DWORD FixtureTick(void) { return GetTickCount(); }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
	(void)h;
	(void)reserved;
	if (reason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(h);
	}
	return TRUE;
}
