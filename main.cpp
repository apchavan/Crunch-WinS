
/*
* Shows details about the logon sessions on Windows system.
*
* Project has set below project's properties:
*
*	https://stackoverflow.com/q/8139480
*	https://stackoverflow.com/q/15967949
*	(1) Properties -> Linker -> Manifest File -> UAC Execution Level (requireAdministrator)
* 
*	(2) Properties -> C/C++ -> Optimization -> Favor Size Or Speed (Favor fast code (/Ot))
*
*/


#include "utils.h"

int main()
{
	SetConsoleTitleA(appName);

	HWND appWindowHWND = GetConsoleWindow();
	ShowWindow(appWindowHWND, SW_SHOWMAXIMIZED);
	SetForegroundWindow(appWindowHWND);

	show_details();

	wprintf_s(TEXT("\n\n(*) Press ENTER/RETURN to exit.."));
	return (0 * getwchar());
}