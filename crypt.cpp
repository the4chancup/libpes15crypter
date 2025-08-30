//Comment here
#include "pch.h"

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "crypt.h"

int32_t bitsToInt32(const unsigned char* bits, bool little_endian = true);
void getChunkSizes(uint8_t*, int*, int);
void generateHeader(char* input, char* output, int* chunkSize, int outSize, const char startByte);


//Create a FileDescriptor15 object
struct FileDescriptor15* createFileDescriptor15()
{
	struct FileDescriptor15* result = new FileDescriptor15;
	if (result)
		memset(result, 0, sizeof(struct FileDescriptor15));
	return result;
}

//Unallocate a FileDescriptor15 object
void destroyFileDescriptor15(struct FileDescriptor15* desc)
{
	if (desc->data)             delete desc->data;
	delete desc;
}

//Decrypt 15 save file data from input and place into a FileDescriptor15
void decryptFile15(struct FileDescriptor15* descriptor, const uint8_t* input)
{
	//First 49 bytes are the header section, so reduce length by that amount
	descriptor->dataSize = descriptor->dataSize - 49;
	//Allocate the necessary memory for the data array and copy it from input to the descriptor (starting from byte 49)
	descriptor->data = (uint8_t*)malloc(descriptor->dataSize);
	memcpy_s(descriptor->data, descriptor->dataSize, &input[49], descriptor->dataSize);
	//The decrypt/encrypt algo is initialized from input[0], so save that in descriptor
	descriptor->startByte = input[0];

	//Data is formatted in 3 chunks, get their sizes
	int chunkSizes[3] = { 0 };
	getChunkSizes(descriptor->data, chunkSizes, 3);
	descriptor->startEditData = chunkSizes[0] + chunkSizes[1] + 8; //Chunk 3 start byte; +8 because 4 byte gap b/w chunk 0 and 1 and 4 byte gap b/w chunk 1 and 2
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
			descriptor->data[num2] ^= (uint8_t)(num %= 255);
			num2++;
		}
		num2 += 4; //Skip 4 bytes between each chunk
	}
	return;
}

//Encrypt 15 save file data from FileDescriptor15, generating a header and returning the byte array of the full EDIT.bin
uint8_t* encryptFile15(const struct FileDescriptor15* descriptor, const char startByte)
{
	int outputLen = descriptor->dataSize + 49; //Add 49 byte header
	uint8_t* output = (uint8_t*)malloc(outputLen);

	int chunkSizes[3] = { 0 };
	getChunkSizes(descriptor->data, chunkSizes, 3);

	generateHeader((char*)descriptor->data, (char*)output, chunkSizes, outputLen, startByte);
	//Copy data from descriptor to output, starting at end of header section
	memcpy_s(&output[49], descriptor->dataSize, descriptor->data, descriptor->dataSize);

	//Reverse the decryption, initialized from startByte
	int num = 0;
	int num2 = 49;
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

void getChunkSizes(uint8_t* input, int* array, int arrayLen)
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