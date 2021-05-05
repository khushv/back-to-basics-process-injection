#include <windows.h>
#include <stdio.h>
#include <tchar.h>

void print_in_hex(unsigned char *buffer, int buf_len) {
	for (int i = 0; i < buf_len; i++) {
		printf("\\x%x", buffer[i]);
	}
	return;
}

unsigned char * xor_encrypt(unsigned char *buffer_src, unsigned char *pass, int buf_len, int key_len) {
	key_len = key_len - 1;
	unsigned char* final = new unsigned char[buf_len];
	unsigned char key_char;

	for (int i = 0; i < buf_len; i++) {
		key_char = pass[i % key_len];
		final[i] = buffer_src[i] ^ key_char;
	}

	return final;
}


int _tmain(int argc, TCHAR* argv[])
{
	unsigned char plain[] = "\xCC";
	int buf_len = sizeof(plain);
	printf("[*] Sizeof initial payload is %d.\n", buf_len);
    unsigned char key[] = "alphaomega";
    int key_len = sizeof(key);

	unsigned char * encrypted = xor_encrypt(plain, key, buf_len, key_len);
 	unsigned char* test = xor_encrypt(encrypted, key, buf_len, key_len);

	if (memcmp(plain, test, buf_len) != 0) {
		printf("[*] Error - strings do not match.\n");
	}
	else {
		printf("[*] Strings match. Good to go. Copy pasta this:\n");
		print_in_hex(encrypted, buf_len);
	}
		
	return 0;
}
