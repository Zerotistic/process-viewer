#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>


#define MAX_NAME 256


BOOL SearchTokenGroupsForSID ( DWORD processID ) 
{
	HANDLE pid = (HANDLE)processID;
	DWORD i, dwSize = 0, dwResult = 0;
	HANDLE hToken;
	PTOKEN_GROUPS pGroupInfo;
	SID_NAME_USE SidType;
	char lpName[MAX_NAME];
	char lpDomain[MAX_NAME];
	PSID pSID = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
	   
	// Open a handle to the access token for the calling process.
	// TOKEN_ADJUST_PRIVILEGES |
	if (!OpenProcessToken( pid, TOKEN_QUERY, &hToken )) 
	{
		printf( "OpenProcessToken Error %u\n", GetLastError() );
		return FALSE;
	}

	// Call GetTokenInformation to get the buffer size.
	if(!GetTokenInformation(hToken, TokenGroups, NULL, dwSize, &dwSize)) 
	{
		dwResult = GetLastError();
		if( dwResult != ERROR_INSUFFICIENT_BUFFER ) {
			printf( "GetTokenInformation Error %u\n", dwResult );
			return FALSE;
		}
	}

	// Allocate the buffer.
	pGroupInfo = (PTOKEN_GROUPS) GlobalAlloc( GPTR, dwSize );

	// Call GetTokenInformation again to get the group information.
	if(! GetTokenInformation(hToken, TokenGroups, pGroupInfo, 
							dwSize, &dwSize ) ) 
	{
		printf( "GetTokenInformation Error %u\n", GetLastError() );
		return FALSE;
	}

	// Create a SID for the BUILTIN\Administrators group.
	if(! AllocateAndInitializeSid( &SIDAuth, 2,
					 SECURITY_BUILTIN_DOMAIN_RID,
					 DOMAIN_ALIAS_RID_ADMINS,
					 0, 0, 0, 0, 0, 0,
					 &pSID) ) 
	{
		printf( "AllocateAndInitializeSid Error %u\n", GetLastError() );
		return FALSE;
	}

	// Loop through the group SIDs looking for the administrator SID.
	for(i=0; i<pGroupInfo->GroupCount; i++) 
	{
		if ( EqualSid(pSID, pGroupInfo->Groups[i].Sid) ) 
		{

			// Lookup the account name and print it.
			dwSize = MAX_NAME;
			if( !LookupAccountSid( NULL, pGroupInfo->Groups[i].Sid,
								  lpName, &dwSize, lpDomain, 
								  &dwSize, &SidType ) ) 
			{
				dwResult = GetLastError();
				if( dwResult == ERROR_NONE_MAPPED )
				   strcpy(lpName, "NONE_MAPPED" );
				else 
				{
					printf("LookupAccountSid Error %u\n", GetLastError());
					return FALSE;
				}
			}
			printf( "Current user is a member of the %s\\%s group\n", 
					lpDomain, lpName );

			// Find out whether the SID is enabled in the token.
			if ( pGroupInfo->Groups[i].Attributes & SE_GROUP_ENABLED )
				printf("The group SID is enabled.\n");
			else if ( pGroupInfo->Groups[i].Attributes & 
							  SE_GROUP_USE_FOR_DENY_ONLY )
				printf("The group SID is a deny-only SID.\n");
			else 
				printf("The group SID is not enabled.\n");
		}
	}

	if ( pSID )
		FreeSid( pSID );
	if ( pGroupInfo )
		GlobalFree( pGroupInfo );
	return TRUE;
}

void PrintProcessNameAndID( DWORD processID )
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	// Get a handle to the process.
	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
								   PROCESS_VM_READ,
								   FALSE, processID );

	// Get the process name.
	if (NULL != hProcess )
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), 
			 &cbNeeded) )
		{
			GetModuleBaseName( hProcess, hMod, szProcessName, 
							   sizeof(szProcessName)/sizeof(TCHAR) );
		}
	}

	// Print the process name and identifier.
	SearchTokenGroupsForSID( processID );
	_tprintf( TEXT("%s  (PID: %u)\n"), szProcessName, processID );

	// Release the handle to the process.
	CloseHandle( hProcess );
}

int StartEnum( void )
{
	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
	{
		return 1;
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.
	for ( i = 0; i < cProcesses; i++ )
	{
		if( aProcesses[i] != 0 )
		{
			PrintProcessNameAndID( aProcesses[i] );
		}
	}

	return 0;
}

int main( void )
{
	printf("Starting the enumeration of all processes..\n");
	StartEnum();
	printf("Enumeration ended...\n");
	return 0;
}
