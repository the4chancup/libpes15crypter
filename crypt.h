#pragma once

#include <windows.h>
#include <Wincrypt.h>
#include <stdio.h>
#include <cstdint>

#ifdef LIBPES15CRYPTER_EXPORTS
#define CRYPTER_EXPORT __declspec(dllexport)
#else
#define CRYPTER_EXPORT 
#endif

struct FileDescriptor15
{
    uint32_t dataSize;
    unsigned char startByte;
    uint32_t chunk0Size; //384
    uint32_t chunk1Size;
    uint32_t chunk2Size;

    uint8_t* chunk0; //Fixed length "Edit file" string
    uint8_t* chunk1lenBytes; //4 bytes that encode length of chunk 1
    uint8_t* chunk1; //PNG
    uint8_t* chunk2lenBytes; //4 bytes that encode length of chunk 2
    uint8_t* data; //Main edit data (chunk 2)
};

extern "C" CRYPTER_EXPORT struct FileDescriptor15* createFileDescriptor15();
extern "C" CRYPTER_EXPORT void destroyFileDescriptor15(struct FileDescriptor15* desc);

extern "C" CRYPTER_EXPORT void decryptFile15(struct FileDescriptor15* descriptor, const uint8_t* input);
extern "C" CRYPTER_EXPORT uint8_t* encryptFile15(const struct FileDescriptor15* descriptor, int* outputLen);

uint8_t* readFile(const char* path, uint32_t* sizePtr);

DWORD md5(BYTE* input, int inputLen, BYTE* computedHash);

