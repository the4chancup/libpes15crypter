#include "pch.h"
#include "crypt.h"

#define MD5LEN  16
#define BUFSIZE 1024

//md5(input, //starting at d
//    chunkSize[0], //get hash of n bytes
//    array); //and write to unsigned char *md 
DWORD md5(BYTE* input, int inputLen, BYTE* computedHash)
{
    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hBuffer[BUFSIZE];
    DWORD cbRead = 0;
    //BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        return dwStatus;
    }

    //Use hProv to create hash in hHash
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }

    //Use hash input data into hHash hash object
    /*
    int startPos, endPos, copyLen;
    startPos = 0;
    endPos = min(startPos + BUFSIZE, inputLen);
    while (true)
    {
        copyLen = endPos - startPos;
        memcpy_s(hBuffer, BUFSIZE, &input[startPos], copyLen);
        if (!CryptHashData(hHash, hBuffer, copyLen, 0))
        {
            dwStatus = GetLastError();
            printf("CryptHashData failed: %d\n", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            return dwStatus;
        }
        startPos = endPos;
        if (startPos >= inputLen) break;
        endPos = min(startPos + BUFSIZE, inputLen);
    }
    */
    if (!CryptHashData(hHash, input, inputLen, 0))
    {
        dwStatus = GetLastError();
        printf("CryptHashData failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        return dwStatus;
    }

    //Retrieve actual hash value from hash object into rgbHash
    cbHash = MD5LEN;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, computedHash, &cbHash, 0))
    {
        dwStatus = GetLastError();
        printf("CryptGetHashParam failed: %d\n", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    //computedHash = rgbHash;

    return dwStatus;
}