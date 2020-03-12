/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreIntegrationTests.h"
#include "SeosCryptoApi.h"
#include "SeosKeyStoreApi.h"
#include "LibDebug/Debug.h"
#include <string.h>

/* Defines -------------------------------------------------------------------*/
// Configuration of the testKeyStoreAES
#define AES_KEY_NAME        "AESKey"
#define SAMPLE_STRING       "0123456789ABCDEF"
#define AES_BLOCK_LEN       16
// Configuration of the testKeyStoreKeyPair
#define PRV_KEY_NAME        "PrvKey"
#define PUB_KEY_NAME        "PubKey"

static const SeosCryptoApi_Key_Spec aes256Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_AES,
        .attribs.exportable = true,
        .params.bits = 256
    }
};
static const SeosCryptoApi_Key_Spec dh64Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_DH_PRV,
        .attribs.exportable = true,
        .params.bits = 64
    }
};
static const SeosCryptoApi_Key_Spec rsa128Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .type = SeosCryptoApi_Key_TYPE_RSA_PRV,
        .attribs.exportable = true,
        .params.bits = 128
    }
};

/* Private variables ---------------------------------------------------------*/
static SeosCryptoApi_Key_Data keyData;

/* Private functions prototypes ----------------------------------------------*/
static bool
importExportKeyPairTest(SeosKeyStoreCtx* keyStoreCtx,
                        SeosCryptoApiH hCrypto,
                        const SeosCryptoApi_Key_Spec* spec);
static seos_err_t
aesEncrypt(SeosCryptoApiH hCrypto,
           SeosCryptoApi_KeyH hKey,
           const char* data,
           size_t inDataSize,
           void* outBuf,
           size_t* outDataSize);

static seos_err_t
aesDecrypt(SeosCryptoApiH hCrypto,
           SeosCryptoApi_KeyH hKey,
           const void* data,
           size_t inDataSize,
           void* outBuf,
           size_t* outDataSize);

/* Public functions -----------------------------------------------------------*/
bool testKeyStoreAES(SeosKeyStoreCtx* keyStoreCtx,
                     SeosCryptoApiH hCrypto)
{
    SeosCryptoApi_KeyH hWriteKey;
    SeosCryptoApi_KeyH hReadKey;
    size_t len;
    size_t decOutSize = 0;
    size_t encOutSize = 0;
    seos_err_t err = SEOS_ERROR_GENERIC;
    char buffEnc[AES_BLOCK_LEN] = {0};
    char buffDec[AES_BLOCK_LEN] = {0};

    /********************************** TestKeyStore_testCase_04 ************************************/
    err = SeosCryptoApi_Key_generate(&hWriteKey, hCrypto, &aes256Spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_generate failed with err %d", err);

    err = aesEncrypt(hCrypto, hWriteKey, SAMPLE_STRING, strlen(SAMPLE_STRING),
                     buffEnc, &decOutSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "aesEncrypt failed with err %d",
                          err);

    /********************************** TestKeyStore_testCase_05 ************************************/
    err = SeosCryptoApi_Key_export(hWriteKey, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_export failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, AES_KEY_NAME, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_Key_free(hWriteKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_free failed with err %d", err);

    /********************************** TestKeyStore_testCase_06 ************************************/
    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreCtx, AES_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);
    Debug_ASSERT(len == sizeof(keyData));

    err = SeosCryptoApi_Key_import(&hReadKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_import failed with err %d", err);

    /********************************** TestKeyStore_testCase_07 ************************************/
    err = aesDecrypt(hCrypto, hReadKey, buffEnc, decOutSize, buffDec,
                     &encOutSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "aesDecrypt failed with err %d",
                          err);
    Debug_ASSERT_PRINTFLN(strncmp(SAMPLE_STRING, buffDec, AES_BLOCK_LEN) == 0,
                          "Decrypted string doesn't match the original!");

    /********************************** TestKeyStore_testCase_08 ************************************/
    err = SeosKeyStoreApi_wipeKeyStore(keyStoreCtx);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(keyStoreCtx, AES_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    return true;
}

bool testKeyStoreKeyPair(SeosKeyStoreCtx* keyStoreCtx,
                         SeosCryptoApiH hCrypto)
{
    bool result = false;

    /********************************** TestKeyStore_testCase_09 - 11 for RSA keys ************************************/
    result = importExportKeyPairTest(keyStoreCtx,
                                     hCrypto,
                                     &rsa128Spec);
    Debug_ASSERT_PRINTFLN(true == result,
                          "importExportKeyPairTest failed for RSA keys");

    /********************************** TestKeyStore_testCase_09 - 11 for DH keys ************************************/
    result = importExportKeyPairTest(keyStoreCtx,
                                     hCrypto,
                                     &dh64Spec);
    Debug_ASSERT_PRINTFLN(true == result,
                          "importExportKeyPairTest failed for DH keys");

    return result;
}

/* Private functions ---------------------------------------------------------*/
static bool
importExportKeyPairTest(SeosKeyStoreCtx* keyStoreCtx,
                        SeosCryptoApiH hCrypto,
                        const SeosCryptoApi_Key_Spec* spec)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoApi_KeyH hPrvKey;
    SeosCryptoApi_KeyH hPubKey;
    size_t len = 0;

    /********************************** TestKeyStore_testCase_09 ************************************/
    err = SeosCryptoApi_Key_generate(&hPrvKey, hCrypto, spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err,
                          "SeosCryptoApi_Key_generate failed with err %d", err);
    err = SeosCryptoApi_Key_makePublic(&hPubKey, hCrypto, hPrvKey,
                                       &spec->key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err,
                          "SeosCryptoApi_Key_makePublic failed with err %d", err);

    /********************************** TestKeyStore_testCase_10 ************************************/
    err = SeosCryptoApi_Key_export(hPrvKey, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_export failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, PRV_KEY_NAME, &keyData,
                                    sizeof(SeosCryptoApi_Key_Data));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_Key_export(hPubKey, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_export failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, PUB_KEY_NAME, &keyData,
                                    sizeof(SeosCryptoApi_Key_Data));
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

    err = SeosCryptoApi_Key_free(hPrvKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_free failed with err %d", err);

    err = SeosCryptoApi_Key_free(hPubKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_Key_free failed with err %d", err);

    return true;
}

static seos_err_t
aesEncrypt(SeosCryptoApiH hCrypto, SeosCryptoApi_KeyH hKey,
           const char* data, size_t inDataSize, void* outBuf, size_t* outDataSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoApi_CipherH hCipher;

    *outDataSize = AES_BLOCK_LEN;

    err = SeosCryptoApi_Cipher_init(&hCipher, hCrypto, hKey,
                                    SeosCryptoApi_Cipher_ALG_AES_ECB_ENC,
                                    NULL, 0);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_Cipher_init failed with error code %d",
                        __func__, err);
        return err;
    }

    err = SeosCryptoApi_Cipher_process(hCipher,
                                       data,
                                       inDataSize,
                                       outBuf,
                                       outDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_Cipher_process failed with error code %d",
                        __func__, err);
    }

    err = SeosCryptoApi_Cipher_free(hCipher);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_Cipher_free failed with error code %d",
                        __func__, err);
    }

    return err;
}

static seos_err_t
aesDecrypt(SeosCryptoApiH hCrypto, SeosCryptoApi_KeyH hKey,
           const void* data, size_t inDataSize, void* outBuf, size_t* outDataSize)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoApi_CipherH hCipher;

    *outDataSize = AES_BLOCK_LEN;

    err = SeosCryptoApi_Cipher_init(&hCipher, hCrypto, hKey,
                                    SeosCryptoApi_Cipher_ALG_AES_ECB_DEC,
                                    NULL, 0);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_Cipher_init failed with error code %d",
                        __func__, err);
        return err;
    }

    err = SeosCryptoApi_Cipher_process(hCipher,
                                       data,
                                       inDataSize,
                                       outBuf,
                                       outDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_Cipher_process failed with error code %d",
                        __func__, err);
    }

    err = SeosCryptoApi_Cipher_free(hCipher);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoApi_Cipher_free failed with error code %d",
                        __func__, err);
    }

    return err;
}
