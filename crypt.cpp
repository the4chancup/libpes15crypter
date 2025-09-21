//Comment here
#include "pch.h"

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "crypt.h"

int headerBytes = 49;

int32_t bitsToInt32(const unsigned char* bits, bool little_endian = true);
void getChunkSizes(const uint8_t*, int*, int);
void generateHeader(char* input, char* output, int* chunkSize, int outSize, const char startByte);


//Create a FileDescriptor15 object
struct FileDescriptor15* createFileDescriptor15()
{
	struct FileDescriptor15* result = new FileDescriptor15;
	if (result)
		memset(result, 0, sizeof(struct FileDescriptor15));
	result->chunk0Size = 384;
	result->chunk0 = new uint8_t[result->chunk0Size];
	memset(result->chunk0, 0, sizeof(uint8_t) * result->chunk0Size);
	result->chunk1lenBytes = new uint8_t[4];
	memset(result->chunk1lenBytes, 0, sizeof(uint8_t) * 4);
	result->chunk2lenBytes = new uint8_t[4];
	memset(result->chunk2lenBytes, 0, sizeof(uint8_t) * 4);
	return result;
}

//Unallocate a FileDescriptor15 object
void destroyFileDescriptor15(struct FileDescriptor15* desc)
{
	if (desc->data)             delete[] desc->data;
	if (desc->chunk1)			delete[] desc->chunk1;
	delete[] desc->chunk0;
	delete[] desc->chunk1lenBytes;
	delete[] desc->chunk2lenBytes;
	delete desc;
}

//Decrypt 15 save file data from input and place into a FileDescriptor15
void decryptFile15(struct FileDescriptor15* descriptor, const uint8_t* input)
{
	//First 49 bytes are the header section, so reduce length by that amount
	descriptor->dataSize = descriptor->dataSize - headerBytes;

	//Data is formatted in 3 chunks, get their sizes
	int chunkSizes[3] = { 0 };
	getChunkSizes(&input[headerBytes], chunkSizes, 3);

	//The decrypt/encrypt algo is initialized from input[0], so save that in descriptor
	descriptor->startByte = input[0];
	descriptor->chunk1Size = chunkSizes[1];
	descriptor->chunk2Size = chunkSizes[2];

	//Place encrypted data in a temporary structure for decryption
	uint8_t* tmpData = new uint8_t[descriptor->dataSize];
	memcpy_s(tmpData, descriptor->dataSize, &input[headerBytes], descriptor->dataSize);
	
	//Then do the decryption operation on descriptor->data, initialized from startByte
	int num = 0;
	int num2 = 0;
	for (int i = 0; i < 3; i++)
	{
		int num3 = descriptor->startByte;
		for (int j = 0; j < chunkSizes[i]; j++)
		{
			num = num3 * 21 + 7;
			num3 = (num %= 32768);
			tmpData[num2] ^= (uint8_t)(num %= 255);
			num2++;
		}
		num2 += 4; //Skip 4 bytes between each chunk
	}

	//Allocate the necessary memory for the data array and copy it from input to the descriptor (starting from byte 49)
	//uint8_t chunk0[384]; //Fixed length "Edit file" string
	//uint8_t chunk1lenBytes[4]; //4 bytes that encode length of chunk 1
	descriptor->chunk1 = new uint8_t[chunkSizes[1]];
	//uint8_t chunk2lenBytes[4]; //4 bytes that encode length of chunk 2
	descriptor->data = new uint8_t[chunkSizes[2]];

	//Copy each portion of input data to the corresponding structure in descriptor
	int offset = 0;
	memcpy_s(descriptor->chunk0, chunkSizes[0], &tmpData[offset], chunkSizes[0]);
	offset += chunkSizes[0];
	memcpy_s(descriptor->chunk1lenBytes, 4, &tmpData[offset], 4);
	offset += 4;
	memcpy_s(descriptor->chunk1, chunkSizes[1], &tmpData[offset], chunkSizes[1]);
	offset += chunkSizes[1];
	memcpy_s(descriptor->chunk2lenBytes, 4, &tmpData[offset], 4);
	offset += 4;
	memcpy_s(descriptor->data, chunkSizes[2], &tmpData[offset], chunkSizes[2]);

	delete[] tmpData;

	return;
}

//Encrypt 15 save file data from FileDescriptor15, generating a header and returning the byte array of the full EDIT.bin
uint8_t* encryptFile15(const struct FileDescriptor15* descriptor, int* outputLen)
{
	*outputLen = descriptor->dataSize + headerBytes; //Add 49 byte header
	uint8_t* output = (uint8_t*)malloc(*outputLen);

	//Copy each portion of descriptor data to output array
	int offset = headerBytes;
	memcpy_s(&output[offset], descriptor->chunk0Size, descriptor->chunk0, descriptor->chunk0Size);
	offset += descriptor->chunk0Size;
	memcpy_s(&output[offset], 4, descriptor->chunk1lenBytes, 4);
	offset += 4;
	memcpy_s(&output[offset], descriptor->chunk1Size, descriptor->chunk1, descriptor->chunk1Size);
	offset += descriptor->chunk1Size;
	memcpy_s(&output[offset], 4, descriptor->chunk2lenBytes, 4);
	offset += 4;
	memcpy_s(&output[offset], descriptor->chunk2Size, descriptor->data, descriptor->chunk2Size);

	int chunkSizes[3] = { descriptor->chunk0Size, descriptor->chunk1Size, descriptor->chunk2Size };

	generateHeader((char*)&output[headerBytes], (char*)output, chunkSizes, *outputLen, descriptor->startByte);

	//Reverse the decryption, initialized from startByte
	int num = 0;
	int num2 = headerBytes;
	for (int i = 0; i < 3; i++)
	{
		int num3 = descriptor->startByte;
		for (int j = 0; j < chunkSizes[i]; j++)
		{
			num = num3 * 21 + 7;
			num3 = (num %= 32768);
			output[num2] ^= (char)(num %= 255);
			num2++;
		}
		num2 += 4;
	}
	return output;
}

int32_t bitsToInt32(const unsigned char* bits, bool little_endian)
{
	int32_t result = 0;
	if (little_endian)
		for (int n = sizeof(result); n >= 0; n--)
			result = (result << 8) + bits[n];
	else
		for (unsigned n = 0; n < sizeof(result); n++)
			result = (result << 8) + bits[n];
	return result;
}

void getChunkSizes(const uint8_t* input, int* array, int arrayLen)
{
	if (arrayLen < 3)
		return;
	array[0] = 384;
	array[1] = bitsToInt32(&input[array[0]]);
	array[2] = bitsToInt32(&input[array[0] + array[1] + 4]);
	return;
}

void generateHeader(char* input, char* output, int* chunkSize, int outSize, const char startByte)
{
	output[0] = startByte; //(char)getBaseValue();
	BYTE* array = new BYTE[16]; //MD5_DIGEST_LENGTH == 16
	DWORD ret = 0;

	//Hash chunk 0
	ret = md5((BYTE*)input, //starting at d
		chunkSize[0], //get hash of n bytes
		array); //and write to unsigned char *md 
	memcpy_s(&output[1], outSize - 1, array, 16); //output[1] because output[0] is the startByte for en/decrypting

	//Hash chunk 1
	ret = md5((BYTE*)&input[chunkSize[0] + 4], chunkSize[1], array); //+4 because there's a 4 byte gap b/w each chunk
	memcpy_s(&output[17], outSize - 17, array, 16); //output[17]: 1 + 16 byte hash for chunk 0

	//Hash chunk 2
	ret = md5((BYTE*)&input[chunkSize[0] + chunkSize[1] + 8], chunkSize[2], array); //+8 because 4 byte gap b/w chunk 0 and 1 and 4 byte gap b/w chunk 1 and 2
	memcpy_s(&output[33], outSize - 33, array, 16); //output[33]: 1 + 16 byte hash for chunk 0 + 16 byte hash for chunk 1
}