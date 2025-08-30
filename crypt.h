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
    char startByte;
    uint8_t* data;
    uint32_t startEditData; // Chunk 3 start byte
};

extern "C" CRYPTER_EXPORT struct FileDescriptor15* createFileDescriptor15();
extern "C" CRYPTER_EXPORT void destroyFileDescriptor15(struct FileDescriptor15* desc);

extern "C" CRYPTER_EXPORT void decryptFile15(struct FileDescriptor15* descriptor, const uint8_t* input);
extern "C" CRYPTER_EXPORT uint8_t* encryptFile15(const struct FileDescriptor15* descriptor, const char startByte);

uint8_t* readFile(const char* path, uint32_t* sizePtr);

DWORD md5(BYTE* input, int inputLen, BYTE* computedHash);

