/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreIntegrationTests.h"
#include "SeosCryptoApi.h"
#include "SeosKeyStoreApi.h"
#include <string.h>
#include "camkes.h"

/* Defines -------------------------------------------------------------------*/
// Configuration of the testKeyStoreAES
#define AES_KEY_NAME        "AESKey"
#define AES_KEY_SIZE        32
#define SAMPLE_STRING       "0123456789ABCDEF"
#define AES_BLOCK_LEN       16

// Configuration of the testKeyStoreKeyPair
#define PRV_KEY_NAME        "PrivateKey"
#define PUB_KEY_NAME        "PublicKey"
#define RSA_KEY_SIZE        1024
#define DH_KEY_SIZE         256

/* Private variables -------------------------------------------------------------------*/
static SeosCryptoKey_RSAPrv rsaPrvKey;
static SeosCryptoKey_RSAPub rsaPubKey;
static SeosCryptoKey_DHPrv dhPrvKey;
static SeosCryptoKey_DHPub dhPubKey;

/* Private functions prototypes ----------------------------------------------*/
static bool
importExportKeyPairTest(SeosKeyStoreCtx* keyStoreCtx,
                        SeosCryptoCtx* cryptoCtx,
                        size_t keySize,
                        unsigned int keyTypePrv,
                        unsigned int keyTypePub,
                        void* pPrvKey,
                        void* pPubKey,
                        size_t exportedKeyLen1,
                        size_t exportedKeyLen2);
static seos_err_t
aesEncrypt(SeosCryptoCtx* cryptoCtx,
           SeosCrypto_KeyHandle keyHandle,
           const char* data,
           size_t inDataSize,
           void** outBuf,
           size_t* outDataSize);

static seos_err_t
aesDecrypt(SeosCryptoCtx* cryptoCtx,
           SeosCrypto_KeyHandle keyHandle,
           const void* data,
           size_t inDataSize,
           void** outBuf,
           size_t* outDataSize);

/* Public functions -----------------------------------------------------------*/
bool testKeyStoreAES(SeosKeyStoreCtx* keyStoreCtx, SeosCryptoCtx* cryptoCtx)
{
    SeosCrypto_KeyHandle writeKey;
    SeosCrypto_KeyHandle readKey;
    SeosCryptoKey_AES aesKeyWrite;
    SeosCryptoKey_AES aesKeyRead;

    size_t exportedKeyLen = sizeof(aesKeyWrite);
    size_t readKeyLen = 0;

    seos_err_t err = SEOS_ERROR_GENERIC;

    size_t aesKeyLen = sizeof(aesKeyWrite);

    void* pKeyWrite = &aesKeyWrite;
    void* pKeyRead = &aesKeyRead;

    char buffEnc[AES_BLOCK_LEN] = {0};
    char buffDec[AES_BLOCK_LEN] = {0};

    void* outputEncrypt = &buffEnc;
    void* outputDecrypt = &buffDec;

    size_t decOutSize = 0;
    size_t encOutSize = 0;

    /********************************** TestKeyStore_testCase_04 ************************************/
    err = SeosCryptoApi_keyInit(cryptoCtx, &writeKey, SeosCryptoKey_Type_AES,
                                SeosCryptoKey_Flags_EXPORTABLE_RAW, AES_KEY_SIZE * 8);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyInit failed with err %d", err);

    err = SeosCryptoApi_keyGenerate(cryptoCtx, writeKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyGenerate failed with err %d", err);

    err = aesEncrypt(cryptoCtx, writeKey, SAMPLE_STRING,
                     strlen(SAMPLE_STRING), &outputEncrypt, &decOutSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "aesEncrypt failed with err %d",
                          err);

    /********************************** TestKeyStore_testCase_05 ************************************/
    err = SeosCryptoApi_keyExport(cryptoCtx, writeKey, NULL, &pKeyWrite,
                                  &exportedKeyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, AES_KEY_NAME, pKeyWrite,
                                    exportedKeyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_keyDeInit(cryptoCtx, writeKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyDeInit failed with err %d", err);

    /********************************** TestKeyStore_testCase_06 ************************************/
    err = SeosKeyStoreApi_getKey(keyStoreCtx, AES_KEY_NAME, pKeyRead, &readKeyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = SeosCryptoApi_keyInit(cryptoCtx, &readKey, SeosCryptoKey_Type_AES,
                                SeosCryptoKey_Flags_EXPORTABLE_RAW, AES_KEY_SIZE * 8);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyInit failed with err %d", err);

    err = SeosCryptoApi_keyImport(cryptoCtx, readKey, NULL, pKeyRead, aesKeyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyImport failed with err %d", err);

    /********************************** TestKeyStore_testCase_07 ************************************/
    err = aesDecrypt(cryptoCtx, readKey, outputEncrypt, decOutSize, &outputDecrypt,
                     &encOutSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "aesDecrypt failed with err %d",
                          err);

    Debug_ASSERT_PRINTFLN(strncmp(SAMPLE_STRING, ((char*)outputDecrypt),
                                  AES_BLOCK_LEN) == 0,
                          "Decrypted string doesn't match the original!");

    /********************************** TestKeyStore_testCase_08 ************************************/
    err = SeosKeyStoreApi_wipeKeyStore(keyStoreCtx);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, AES_KEY_NAME, pKeyRead, &readKeyLen);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    return true;
}

bool testKeyStoreKeyPair(SeosKeyStoreCtx* keyStoreCtx, SeosCryptoCtx* cryptoCtx)
{
    /********************************** RSA key-pair ************************************/
    void* pRsaPrvKey = &rsaPrvKey;
    void* pRsaPubKey = &rsaPubKey;
    size_t exportedKeyLenRSA1 = sizeof(rsaPrvKey);
    size_t exportedKeyLenRSA2 = sizeof(rsaPubKey);

    /********************************** DH key-pair ************************************/
    void* pdhPrvKey = &dhPrvKey;
    void* pdhPubKey = &dhPubKey;
    size_t exportedKeyLenDH1 = sizeof(dhPrvKey);
    size_t exportedKeyLenDH2 = sizeof(dhPubKey);

    bool result = false;

    /********************************** TestKeyStore_testCase_09 - 11 for RSA keys ************************************/
    result = importExportKeyPairTest(keyStoreCtx,
                                     cryptoCtx,
                                     RSA_KEY_SIZE,
                                     SeosCryptoKey_Type_RSA_PRV,
                                     SeosCryptoKey_Type_RSA_PUB,
                                     pRsaPrvKey,
                                     pRsaPubKey,
                                     exportedKeyLenRSA1,
                                     exportedKeyLenRSA2);
    Debug_ASSERT_PRINTFLN(true == result,
                          "importExportKeyPairTest failed for RSA keys");

    /********************************** TestKeyStore_testCase_09 - 11 for DH keys ************************************/
    result = importExportKeyPairTest(keyStoreCtx,
                                     cryptoCtx,
                                     DH_KEY_SIZE,
                                     SeosCryptoKey_Type_DH_PRV,
                                     SeosCryptoKey_Type_DH_PUB,
                                     pdhPrvKey,
                                     pdhPubKey,
                                     exportedKeyLenDH1,
                                     exportedKeyLenDH2);
    Debug_ASSERT_PRINTFLN(true == result,
                          "importExportKeyPairTest failed for DH keys");

    return result;
}

/* Private functions ---------------------------------------------------------*/
static bool
importExportKeyPairTest(SeosKeyStoreCtx* keyStoreCtx,
                        SeosCryptoCtx* cryptoCtx,
                        size_t keySize,
                        unsigned int keyTypePrv,
                        unsigned int keyTypePub,
                        void* pPrvKey,
                        void* pPubKey,
                        size_t exportedKeyLen1,
                        size_t exportedKeyLen2)
{
    SeosCrypto_KeyHandle prvKeyHandle;
    SeosCrypto_KeyHandle pubKeyHandle;
    seos_err_t err = SEOS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_09 ************************************/
    err = SeosCryptoApi_keyInit(cryptoCtx, &prvKeyHandle,
                                keyTypePrv, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                keySize);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err,
                          "SeosCryptoApi_keyInit failed with err %d", err);

    err = SeosCryptoApi_keyInit(cryptoCtx, &pubKeyHandle,
                                keyTypePub, SeosCryptoKey_Flags_EXPORTABLE_RAW,
                                keySize);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err,
                          "SeosCryptoApi_keyInit failed with err %d", err);

    err = SeosCryptoApi_keyGeneratePair(cryptoCtx, prvKeyHandle,
                                        pubKeyHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err,
                          "SeosCryptoApi_keyGeneratePair failed with err %d", err);

    /********************************** TestKeyStore_testCase_10 ************************************/
    err = SeosCryptoApi_keyExport(cryptoCtx, prvKeyHandle, NULL, &pPrvKey,
                                  &exportedKeyLen1);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);

    err = SeosCryptoApi_keyExport(cryptoCtx, pubKeyHandle, NULL, &pPubKey,
                                  &exportedKeyLen2);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, PRV_KEY_NAME, pPrvKey,
                                    exportedKeyLen1);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, PUB_KEY_NAME, pPubKey,
                                    exportedKeyLen2);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    /********************************** TestKeyStore_testCase_11 ************************************/
    err = SeosKeyStoreApi_deleteKey(keyStoreCtx, PRV_KEY_NAME);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_deleteKey failed with err %d", err);

    err = SeosKeyStoreApi_deleteKey(keyStoreCtx, PUB_KEY_NAME);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_deleteKey failed with err %d", err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, PRV_KEY_NAME, pPrvKey,
                                 &exportedKeyLen1);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, PUB_KEY_NAME, pPubKey,
                                 &exportedKeyLen2);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    err = SeosCryptoApi_keyDeInit(cryptoCtx, prvKeyHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyDeInit failed with err %d", err);

    err = SeosCryptoApi_keyDeInit(cryptoCtx, pubKeyHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyDeInit failed with err %d", err);

    return true;
}

static seos_err_t
aesEncrypt(SeosCryptoCtx* cryptoCtx, SeosCrypto_KeyHandle keyHandle,
           const char* data, size_t inDataSize, void** outBuf, size_t* outDataSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle handle;

    *outDataSize = AES_BLOCK_LEN;

    err = SeosCryptoApi_cipherInit(cryptoCtx,
                                   &handle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_ENC,
                                   keyHandle,
                                   NULL, 0);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherInit failed with error code %d",
                        __func__, err);
        return err;
    }

    err = SeosCryptoApi_cipherUpdate(cryptoCtx,
                                     handle,
                                     data,
                                     inDataSize,
                                     outBuf,
                                     outDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherUpdate failed with error code %d",
                        __func__, err);
    }

    err = SeosCryptoApi_cipherClose(cryptoCtx, handle);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherClose failed with error code %d",
                        __func__, err);
    }

    return err;
}

static seos_err_t
aesDecrypt(SeosCryptoCtx* cryptoCtx, SeosCrypto_KeyHandle keyHandle,
           const void* data, size_t inDataSize, void** outBuf, size_t* outDataSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_CipherHandle handle;

    *outDataSize = AES_BLOCK_LEN;

    err = SeosCryptoApi_cipherInit(cryptoCtx,
                                   &handle,
                                   SeosCryptoCipher_Algorithm_AES_ECB_DEC,
                                   keyHandle,
                                   NULL, 0);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherInit failed with error code %d",
                        __func__, err);
        return err;
    }

    err = SeosCryptoApi_cipherUpdate(cryptoCtx,
                                     handle,
                                     data,
                                     inDataSize,
                                     outBuf,
                                     outDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherUpdate failed with error code %d",
                        __func__, err);
    }

    err = SeosCryptoApi_cipherClose(cryptoCtx, handle);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherClose failed with error code %d",
                        __func__, err);
    }

    return err;
}
