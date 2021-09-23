#pragma once


// https://stackoverflow.com/a/46845072
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif // !SECURITY_WIN32

#include <Windows.h>
#include <stdio.h>
#include <lmcons.h>
#include <NTSecAPI.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Advapi32.lib")

constexpr char* appName = const_cast<char*>("Crunch WinS");
constexpr WCHAR* wAppName = const_cast<WCHAR*>(TEXT("Crunch WinS"));

void clearInputStreamStdin();
void show_details(void);
void extract_sessions(void);
void print_horizontal_line(void);
void print_session_data(PSECURITY_LOGON_SESSION_DATA);
void show_fake_progress(void);
WCHAR* get_logon_type(int);


void clearInputStreamStdin()
{
	/*
	* Clean-up the input stream 'stdin' to correctly take input character/string from user.
	*/

	long long ch = '\0';
	while ((ch = getchar()) != '\n' && ch != EOF);
}

void show_details()
{
	WCHAR userName[(UNLEN + 1)];
	SecureZeroMemory(userName, sizeof(userName));

	DWORD userNameLength = (DWORD)(UNLEN + 1);
	if (!GetUserNameW(userName, &userNameLength))
	{
		SecureZeroMemory(userName, sizeof(userName));
		return;
	}
	wprintf_s(TEXT("\nWelcome, '%ws'..! '%ws' will extract Windows logon Sessions on your system..\n\n"),
		userName, wAppName);

	Sleep(3000);
	show_fake_progress();

	wprintf_s(TEXT("\nWe got detailed session data..! Want to see..? (y/n) : "));
	WCHAR choice = 'y';
	choice = static_cast<WCHAR>(tolower(getwchar()));

	if (choice == 'y')
	{
		wprintf_s(TEXT("\n\n(*) Details will be shown here.."));
		Sleep(3000);
		_wsystem(TEXT("cls"));

		wprintf_s(TEXT("\n\nYour logon name --> %ws\n"), userName);
		extract_sessions();
		clearInputStreamStdin();
	}
	else {
		wprintf_s(TEXT("\n\n(*) You're kidding us by this choice.. ;-)"));
		wprintf_s(TEXT("\n\n(*) Details still be shown here.."));
		Sleep(4000);
		_wsystem(TEXT("cls"));

		wprintf_s(TEXT("\n\nYour logon name --> %ws\n"), userName);
		extract_sessions();
		if (choice != '\0' && choice != 10 && choice != 13)
			clearInputStreamStdin();
	}
}

void show_fake_progress()
{
	/*
	* https://stackoverflow.com/a/14539953
	*/
	float progress = 0.0f;
	while (progress < 1.0f) {
		Sleep(50);
		float barWidth = 80.0f;

		wprintf_s(TEXT("["));
		float pos = barWidth * progress;
		for (float i = 0.0f; i < barWidth; i += 1.0f) {
			if (i <= pos)
				wprintf_s(TEXT("="));
			else
				wprintf_s(TEXT(" "));
		}
		wprintf_s(
			((progress * 100.0f) + 0.01f >= 100.0f) ? TEXT("] 100 %% -- Done..! :-)\r")
			: TEXT("] %d %% Extracting..\r"), int(progress * 100.0f));
		progress += 0.01f;
	}
	wprintf_s(TEXT("\n"));
}

void extract_sessions()
{

	HANDLE tokenHandle = NULL, processHandle = GetCurrentProcess();
	if (!OpenProcessToken(processHandle,
		(TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_READ | TOKEN_EXECUTE | TOKEN_WRITE),
		&tokenHandle))
	{
		wprintf_s(TEXT("%ld"), GetLastError());
		CloseHandle(tokenHandle);
		CloseHandle(processHandle);
		return;
	}

	TOKEN_STATISTICS tokenInformation;
	DWORD tokenInfoLength = (DWORD)(sizeof(TOKEN_STATISTICS) + SECURITY_MAX_SID_SIZE);
	DWORD returnLength = (DWORD)(0);
	if (!GetTokenInformation(tokenHandle, TokenStatistics, &tokenInformation, tokenInfoLength, &returnLength))
	{
		wprintf_s(TEXT("%ld"), GetLastError());
		CloseHandle(tokenHandle);
		CloseHandle(processHandle);
		return;
	}
	wprintf_s(TEXT("Your logon session LUID --> %ld-%ld\n"),
		tokenInformation.AuthenticationId.HighPart, tokenInformation.AuthenticationId.LowPart);

	WCHAR computerNameBuffer[256];
	DWORD computerNameBufferLength = (DWORD)(256);
	SecureZeroMemory(computerNameBuffer, sizeof(computerNameBuffer));
	if (!GetComputerNameExW(ComputerNameDnsHostname, computerNameBuffer, &computerNameBufferLength))
	{
		wprintf_s(TEXT("%ld"), GetLastError());
		return;
	}
	wprintf_s(TEXT("Computer name --> %ws\n"), computerNameBuffer);

	ULONG logonSessionCount = 0UL;
	PLUID logonSessionList;
	NTSTATUS ntsResult = LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList);
	if (ntsResult)  // ntsResult != STATUS_SUCCESS || ntsResult != (NTSTATUS)0x00000000L
	{
		wprintf_s(TEXT("%lu"), LsaNtStatusToWinError(ntsResult));
		CloseHandle(tokenHandle);
		CloseHandle(processHandle);
		return;
	}
	wprintf_s(TEXT("Total sessions found --> %ld\n"), logonSessionCount);

	if (logonSessionCount > 0UL)
	{
		wprintf_s(TEXT("\n\n(*) Extracting %ld logon sessions info : \n"), logonSessionCount);
		print_horizontal_line();
	}
	PSECURITY_LOGON_SESSION_DATA logonSessionData = NULL;
	for (ULONG idx = 0; idx < logonSessionCount; idx++)
	{
		SecureZeroMemory(&logonSessionData, sizeof(logonSessionData));
		ntsResult = LsaGetLogonSessionData(&logonSessionList[idx], &logonSessionData);
		if (ntsResult)    // ntsResult != STATUS_SUCCESS || ntsResult != (NTSTATUS)0x00000000L
			break;

		wprintf_s(TEXT("{%lu}\n"), idx + 1);
		print_session_data(logonSessionData);
		print_horizontal_line();
	}

	SecureZeroMemory(&logonSessionData, sizeof(logonSessionData));
	LsaFreeReturnBuffer(logonSessionData);
	CloseHandle(tokenHandle);
	CloseHandle(processHandle);
}

WCHAR* get_logon_type(int logonEnumId)
{
	switch (logonEnumId)
	{
	default:  // case UndefinedLogonType:
		return const_cast<PWCHAR>(TEXT("UndefinedLogonType"));
	case Interactive:
		return const_cast<PWCHAR>(TEXT("Interactive"));
	case Network:
		return const_cast<PWCHAR>(TEXT("Network"));
	case Batch:
		return const_cast<PWCHAR>(TEXT("Batch"));
	case Service:
		return const_cast<PWCHAR>(TEXT("Service"));
	case Proxy:
		return const_cast<PWCHAR>(TEXT("Proxy"));
	case Unlock:
		return const_cast<PWCHAR>(TEXT("Unlock"));
	case NetworkCleartext:
		return const_cast<PWCHAR>(TEXT("NetworkCleartext"));
	case NewCredentials:
		return const_cast<PWCHAR>(TEXT("NewCredentials"));
	case RemoteInteractive:
		return const_cast<PWCHAR>(TEXT("RemoteInteractive"));
	case CachedInteractive:
		return const_cast<PWCHAR>(TEXT("CachedInteractive"));
	case CachedRemoteInteractive:
		return const_cast<PWCHAR>(TEXT("CachedRemoteInteractive"));
	case CachedUnlock:
		return const_cast<PWCHAR>(TEXT("CachedUnlock"));
	}
}

void print_horizontal_line()
{
	for (size_t idx = 0; idx < 128; idx++)
	{
		wprintf_s(TEXT("~"));
	}
	wprintf_s(TEXT("\n"));
}

void print_session_data(PSECURITY_LOGON_SESSION_DATA logonSessionData)
{
	wprintf_s(TEXT("Session data size : %ld\n"), logonSessionData->Size);

	wprintf_s(TEXT("Logon ID (LUID) : %ld-%ld\n"), logonSessionData->LogonId.HighPart, logonSessionData->LogonId.LowPart);

	wprintf_s(TEXT("UserName : %ws\n"),
		(logonSessionData->UserName.Buffer[0] == '\0') ? TEXT("N.A. (Not Available)")
		: logonSessionData->UserName.Buffer);

	wprintf_s(TEXT("Logon domain : %ws\n"),
		(logonSessionData->LogonDomain.Buffer[0] == '\0') ? TEXT("N.A. (Not Available)")
		: logonSessionData->LogonDomain.Buffer);

	wprintf_s(TEXT("Authentication package : %s\n"),
		(logonSessionData->AuthenticationPackage.Buffer[0] == '\0') ? TEXT("N.A. (Not Available)")
		: logonSessionData->AuthenticationPackage.Buffer);

	wprintf_s(TEXT("Logon type : %ws\n"), get_logon_type(logonSessionData->LogonType));

	wprintf_s(TEXT("Terminal services session identifier : %ld\n"), logonSessionData->Session);

	wprintf_s(TEXT("User's security identifier (SID) : %p\n"), logonSessionData->Sid);

	wprintf_s(TEXT("The time the session owner logged on : %lld\n"),
		logonSessionData->LogonTime.QuadPart
	);

	wprintf_s(TEXT("Logon server : %ws\n"),
		(logonSessionData->LogonServer.Buffer[0] == '\0') ? TEXT("N.A. (Not Available)")
		: logonSessionData->LogonServer.Buffer);

	wprintf_s(TEXT("DNS name for the owner of the logon session : %ws\n"),
		(logonSessionData->DnsDomainName.Buffer[0] == '\0') ? TEXT("N.A. (Not Available)")
		: logonSessionData->DnsDomainName.Buffer);

	wprintf_s(TEXT("User principal name (UPN) for the owner of the logon session : %ws\n"),
		(logonSessionData->Upn.Buffer[0] == '\0') ? TEXT("N.A. (Not Available)")
		: logonSessionData->Upn.Buffer);

	wprintf_s(TEXT("Value of the user flags for the logon session : %ld\n"), logonSessionData->UserFlags);

	wprintf_s(TEXT("The last logon session info :- \n"));

	wprintf_s(
		(logonSessionData->LastLogonInfo.LastSuccessfulLogon.QuadPart == 0LL) ? TEXT("\tLast successful : N.A. (Not Available)\n")
		: TEXT("\tLast successful : %lld\n"), logonSessionData->LastLogonInfo.LastSuccessfulLogon.QuadPart
	);

	wprintf_s(
		(logonSessionData->LastLogonInfo.LastFailedLogon.QuadPart == 0LL) ? TEXT("\tLast failed : N.A. (Not Available)\n")
		: TEXT("\tLast failed : %lld\n"), logonSessionData->LastLogonInfo.LastFailedLogon.QuadPart
	);

	wprintf_s(TEXT("\tNumber of failed attempts to log on since the last successful log on : %ld\n"),
		logonSessionData->LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon);

	if (logonSessionData->LogonScript.Buffer[0] != '\0')
		wprintf_s(TEXT("Logon script used : %ws\n"), logonSessionData->LogonScript.Buffer);

	if (logonSessionData->ProfilePath.Buffer[0] != '\0')
		wprintf_s(TEXT("User's profile path : %ws\n"), logonSessionData->ProfilePath.Buffer);

	if (logonSessionData->HomeDirectory.Buffer[0] != '\0')
		wprintf_s(TEXT("Home directory for logon session : %ws\n"), logonSessionData->HomeDirectory.Buffer);

	if (logonSessionData->HomeDirectoryDrive.Buffer[0] != '\0')
		wprintf_s(TEXT("Drive of Home directory for logon session : %ws\n"), logonSessionData->HomeDirectoryDrive.Buffer);

	if (logonSessionData->LogoffTime.QuadPart != 0LL)
		wprintf_s(TEXT("The time stamp of when the session user logged off : %lld\n"), logonSessionData->LogoffTime.QuadPart);
}
