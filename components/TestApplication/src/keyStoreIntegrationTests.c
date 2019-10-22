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
#define PRV_KEY_NAME        "PrvKey"
#define PUB_KEY_NAME        "PubKey"
#define RSA_KEY_SIZE        1024
#define DH_KEY_SIZE         256

static const SeosCryptoKey_Spec aes256Spec =
{
    .type = SeosCryptoKey_SpecType_BITS,
    .key = {
        .type = SeosCryptoKey_Type_AES,
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW,
        .params.bits = 256
    }
};
static const SeosCryptoKey_Spec dh64Spec =
{
    .type = SeosCryptoKey_SpecType_BITS,
    .key = {
        .type = SeosCryptoKey_Type_DH_PRV,
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW,
        .params.bits = 64
    }
};
static const SeosCryptoKey_Spec rsa128Spec =
{
    .type = SeosCryptoKey_SpecType_BITS,
    .key = {
        .type = SeosCryptoKey_Type_RSA_PRV,
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW,
        .params.bits = 128
    }
};

/* Private variables ---------------------------------------------------------*/
static SeosCryptoKey_Data keyData;

/* Private functions prototypes ----------------------------------------------*/
static bool
importExportKeyPairTest(SeosKeyStoreCtx*            keyStoreCtx,
                        SeosCryptoCtx*              cryptoCtx,
                        const SeosCryptoKey_Spec*   spec);
static seos_err_t
aesEncrypt(SeosCryptoCtx* cryptoCtx,
           SeosCrypto_KeyHandle keyHandle,
           const char* data,
           size_t inDataSize,
           void* outBuf,
           size_t* outDataSize);

static seos_err_t
aesDecrypt(SeosCryptoCtx* cryptoCtx,
           SeosCrypto_KeyHandle keyHandle,
           const void* data,
           size_t inDataSize,
           void* outBuf,
           size_t* outDataSize);

/* Public functions -----------------------------------------------------------*/
bool testKeyStoreAES(SeosKeyStoreCtx* keyStoreCtx, SeosCryptoCtx* cryptoCtx)
{
    SeosCrypto_KeyHandle writeKey;
    SeosCrypto_KeyHandle readKey;
    size_t len;
    size_t decOutSize = 0;
    size_t encOutSize = 0;
    seos_err_t err = SEOS_ERROR_GENERIC;
    char buffEnc[AES_BLOCK_LEN] = {0};
    char buffDec[AES_BLOCK_LEN] = {0};

    /********************************** TestKeyStore_testCase_04 ************************************/
    err = SeosCryptoApi_keyGenerate(cryptoCtx, &writeKey, &aes256Spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyGenerate failed with err %d", err);

    err = aesEncrypt(cryptoCtx, writeKey, SAMPLE_STRING,
                     strlen(SAMPLE_STRING), buffEnc, &decOutSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "aesEncrypt failed with err %d",
                          err);

    /********************************** TestKeyStore_testCase_05 ************************************/
    err = SeosCryptoApi_keyExport(cryptoCtx, writeKey, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, AES_KEY_NAME, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_keyFree(cryptoCtx, writeKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyFree failed with err %d", err);

    /********************************** TestKeyStore_testCase_06 ************************************/
    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreCtx, AES_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);
    Debug_ASSERT(len == sizeof(keyData));

    err = SeosCryptoApi_keyImport(cryptoCtx, &readKey, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyImport failed with err %d", err);

    /********************************** TestKeyStore_testCase_07 ************************************/
    err = aesDecrypt(cryptoCtx, readKey, buffEnc, decOutSize, buffDec,
                     &encOutSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "aesDecrypt failed with err %d",
                          err);

    Debug_ASSERT_PRINTFLN(strncmp(SAMPLE_STRING, buffDec, AES_BLOCK_LEN) == 0,
                          "Decrypted string doesn't match the original!");

    /********************************** TestKeyStore_testCase_08 ************************************/
    err = SeosKeyStoreApi_wipeKeyStore(keyStoreCtx);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreCtx, AES_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    return true;
}

bool testKeyStoreKeyPair(SeosKeyStoreCtx* keyStoreCtx, SeosCryptoCtx* cryptoCtx)
{
    bool result = false;

    /********************************** TestKeyStore_testCase_09 - 11 for RSA keys ************************************/
    result = importExportKeyPairTest(keyStoreCtx,
                                     cryptoCtx,
                                     &rsa128Spec);
    Debug_ASSERT_PRINTFLN(true == result,
                          "importExportKeyPairTest failed for RSA keys");

    /********************************** TestKeyStore_testCase_09 - 11 for DH keys ************************************/
    result = importExportKeyPairTest(keyStoreCtx,
                                     cryptoCtx,
                                     &dh64Spec);
    Debug_ASSERT_PRINTFLN(true == result,
                          "importExportKeyPairTest failed for DH keys");

    return result;
}

/* Private functions ---------------------------------------------------------*/
static bool
importExportKeyPairTest(SeosKeyStoreCtx*            keyStoreCtx,
                        SeosCryptoCtx*              cryptoCtx,
                        const SeosCryptoKey_Spec*   spec)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCrypto_KeyHandle prvKeyHandle;
    SeosCrypto_KeyHandle pubKeyHandle;
    size_t len = 0;

    /********************************** TestKeyStore_testCase_09 ************************************/
    err = SeosCryptoApi_keyGenerate(cryptoCtx, &prvKeyHandle, spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err,
                          "SeosCryptoApi_keyGenerate failed with err %d", err);
    err = SeosCryptoApi_keyMakePublic(cryptoCtx, &pubKeyHandle, prvKeyHandle,
                                      &spec->key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err,
                          "SeosCryptoApi_keyMakePublic failed with err %d", err);

    /********************************** TestKeyStore_testCase_10 ************************************/
    err = SeosCryptoApi_keyExport(cryptoCtx, prvKeyHandle, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, PRV_KEY_NAME, &keyData,
                                    sizeof(SeosCryptoKey_Data));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_keyExport(cryptoCtx, pubKeyHandle, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, PUB_KEY_NAME, &keyData,
                                    sizeof(SeosCryptoKey_Data));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    /********************************** TestKeyStore_testCase_11 ************************************/
    err = SeosKeyStoreApi_deleteKey(keyStoreCtx, PRV_KEY_NAME);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_deleteKey failed with err %d", err);

    err = SeosKeyStoreApi_deleteKey(keyStoreCtx, PUB_KEY_NAME);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_deleteKey failed with err %d", err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, PRV_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, PUB_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    err = SeosCryptoApi_keyFree(cryptoCtx, prvKeyHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyFree failed with err %d", err);

    err = SeosCryptoApi_keyFree(cryptoCtx, pubKeyHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyFree failed with err %d", err);

    return true;
}

static seos_err_t
aesEncrypt(SeosCryptoCtx* cryptoCtx, SeosCrypto_KeyHandle keyHandle,
           const char* data, size_t inDataSize, void* outBuf, size_t* outDataSize)
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

    err = SeosCryptoApi_cipherProcess(cryptoCtx,
                                      handle,
                                      data,
                                      inDataSize,
                                      outBuf,
                                      outDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherProcess failed with error code %d",
                        __func__, err);
    }

    err = SeosCryptoApi_cipherFree(cryptoCtx, handle);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherFree failed with error code %d",
                        __func__, err);
    }

    return err;
}

static seos_err_t
aesDecrypt(SeosCryptoCtx* cryptoCtx, SeosCrypto_KeyHandle keyHandle,
           const void* data, size_t inDataSize, void* outBuf, size_t* outDataSize)
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

    err = SeosCryptoApi_cipherProcess(cryptoCtx,
                                      handle,
                                      data,
                                      inDataSize,
                                      outBuf,
                                      outDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherProcess failed with error code %d",
                        __func__, err);
    }

    err = SeosCryptoApi_cipherFree(cryptoCtx, handle);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_cipherFree failed with error code %d",
                        __func__, err);
    }

    return err;
}
