#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define IOCTL_TEST_CMD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
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
        printf("Failed to open device. Error: %ld\n", GetLastError());
        return 1;
    }

    size_t* inputbuf = (size_t*)calloc(1, 0x100);
    if (inputbuf == NULL) {
        printf("Memory allocation failed\n");
        CloseHandle(hDevice);
        return 1;
    }

    char outputbuf[256] = { 0 };
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(
        hDevice,
        0x9C40240B,
        inputbuf,
        0x100,
        (LPVOID)outputbuf,
        sizeof(outputbuf),
        &bytesReturned,
        NULL
    );

    if (result) {
        printf("IOCTL command sent successfully\n");
        hexdump(inputbuf, 0x100);
    } else {
        printf("Failed to send IOCTL command. Error: %ld\n", GetLastError());
    }

    free(inputbuf);
    CloseHandle(hDevice);
    return 0;
}

