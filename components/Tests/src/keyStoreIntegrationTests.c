/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreIntegrationTests.h"
#include "OS_Crypto.h"
#include "OS_Keystore.h"
#include "LibDebug/Debug.h"
#include "LibMacros/Test.h"
#include <string.h>

/* Defines -------------------------------------------------------------------*/
// Configuration of the testKeyStoreAES
#define AES_KEY_NAME        "AESKey"
#define SAMPLE_STRING       "0123456789ABCDEF"
#define AES_BLOCK_LEN       16
// Configuration of the testKeyStoreKeyPair
#define PRV_KEY_NAME        "PrvKey"
#define PUB_KEY_NAME        "PubKey"

static const OS_CryptoKey_Spec_t aes256Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_AES,
        .attribs.keepLocal = true,
        .params.bits = 256
    }
};
static const OS_CryptoKey_Spec_t dh64Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_DH_PRV,
        .attribs.keepLocal = true,
        .params.bits = 64
    }
};
static const OS_CryptoKey_Spec_t rsa128Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_RSA_PRV,
        .attribs.keepLocal = true,
        .params.bits = 128
    }
};

/* Private variables ---------------------------------------------------------*/
static OS_CryptoKey_Data_t keyData;

/* Private functions prototypes ----------------------------------------------*/
static bool
importExportKeyPairTest(
    OS_Keystore_Handle_t       hKeystore,
    OS_Crypto_Handle_t         hCrypto,
    const OS_CryptoKey_Spec_t* spec);
static OS_Error_t
aesEncrypt(
    OS_Crypto_Handle_t    hCrypto,
    OS_CryptoKey_Handle_t hKey,
    const char*           data,
    size_t                inDataSize,
    void*                 outBuf,
    size_t*               outDataSize);
static OS_Error_t
aesDecrypt(
    OS_Crypto_Handle_t    hCrypto,
    OS_CryptoKey_Handle_t hKey,
    const void*           data,
    size_t                inDataSize,
    void*                 outBuf,
    size_t*               outDataSize);

/* Public functions -----------------------------------------------------------*/
void testKeyStoreAES(
    OS_Keystore_Handle_t hKeystore,
    OS_Crypto_Handle_t   hCrypto)
{
    TEST_START();

    OS_CryptoKey_Handle_t hWriteKey;
    OS_CryptoKey_Handle_t hReadKey;
    size_t len;
    size_t decOutSize = 0;
    size_t encOutSize = 0;
    OS_Error_t err = OS_ERROR_GENERIC;
    char buffEnc[AES_BLOCK_LEN] = {0};
    char buffDec[AES_BLOCK_LEN] = {0};

    /********************************** TestKeyStore_testCase_04 ************************************/
    err = OS_CryptoKey_generate(&hWriteKey, hCrypto, &aes256Spec);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = aesEncrypt(hCrypto, hWriteKey, SAMPLE_STRING, strlen(SAMPLE_STRING),
                     buffEnc, &decOutSize);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    /********************************** TestKeyStore_testCase_05 ************************************/
    err = OS_CryptoKey_export(hWriteKey, &keyData);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_storeKey(hKeystore, AES_KEY_NAME, &keyData,
                               sizeof(keyData));
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_free(hWriteKey);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    /********************************** TestKeyStore_testCase_06 ************************************/
    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hKeystore, AES_KEY_NAME, &keyData, &len);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);
    ASSERT_EQ_SZ(sizeof(keyData), len);

    err = OS_CryptoKey_import(&hReadKey, hCrypto, &keyData);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    /********************************** TestKeyStore_testCase_07 ************************************/
    err = aesDecrypt(hCrypto, hReadKey, buffEnc, decOutSize, buffDec,
                     &encOutSize);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);
    // Decrypted string shall match the original!
    ASSERT_EQ_INT(0, strncmp(SAMPLE_STRING, buffDec, AES_BLOCK_LEN));

    /********************************** TestKeyStore_testCase_08 ************************************/
    err = OS_Keystore_wipeKeystore(hKeystore);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hKeystore, AES_KEY_NAME, &keyData, &len);
    ASSERT_EQ_OS_ERR(OS_ERROR_NOT_FOUND, err);

    TEST_FINISH();
}

void testKeyStoreKeyPair(
    OS_Keystore_Handle_t hKeystore,
    OS_Crypto_Handle_t   hCrypto)
{
    TEST_START();

    bool result = false;

    /********************************** TestKeyStore_testCase_09 - 11 for RSA keys ************************************/
    result = importExportKeyPairTest(hKeystore,
                                     hCrypto,
                                     &rsa128Spec);
    ASSERT_TRUE(result);

    /********************************** TestKeyStore_testCase_09 - 11 for DH keys ************************************/
    result = importExportKeyPairTest(hKeystore,
                                     hCrypto,
                                     &dh64Spec);
    ASSERT_TRUE(result);

    TEST_FINISH();
}

/* Private functions ---------------------------------------------------------*/
static bool
importExportKeyPairTest(
    OS_Keystore_Handle_t       hKeystore,
    OS_Crypto_Handle_t         hCrypto,
    const OS_CryptoKey_Spec_t* spec)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    OS_CryptoKey_Handle_t hPrvKey;
    OS_CryptoKey_Handle_t hPubKey;
    size_t len = 0;

    /********************************** TestKeyStore_testCase_09 ************************************/
    err = OS_CryptoKey_generate(&hPrvKey, hCrypto, spec);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_makePublic(&hPubKey, hCrypto, hPrvKey,
                                  &spec->key.attribs);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    /********************************** TestKeyStore_testCase_10 ************************************/
    err = OS_CryptoKey_export(hPrvKey, &keyData);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_storeKey(hKeystore, PRV_KEY_NAME, &keyData,
                               sizeof(OS_CryptoKey_Data_t));
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_export(hPubKey, &keyData);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_storeKey(hKeystore, PUB_KEY_NAME, &keyData,
                               sizeof(OS_CryptoKey_Data_t));
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    /********************************** TestKeyStore_testCase_11 ************************************/
    err = OS_Keystore_deleteKey(hKeystore, PRV_KEY_NAME);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_deleteKey(hKeystore, PUB_KEY_NAME);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_loadKey(hKeystore, PRV_KEY_NAME, &keyData, &len);
    ASSERT_EQ_OS_ERR(OS_ERROR_NOT_FOUND, err);

    err = OS_Keystore_loadKey(hKeystore, PUB_KEY_NAME, &keyData, &len);
    ASSERT_EQ_OS_ERR(OS_ERROR_NOT_FOUND, err);

    err = OS_CryptoKey_free(hPrvKey);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_free(hPubKey);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    return true;
}

static OS_Error_t
aesEncrypt(
    OS_Crypto_Handle_t    hCrypto,
    OS_CryptoKey_Handle_t hKey,
    const char*           data,
    size_t                inDataSize,
    void*                 outBuf,
    size_t*               outDataSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    OS_CryptoCipher_Handle_t hCipher;

    *outDataSize = AES_BLOCK_LEN;

    err = OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                               OS_CryptoCipher_ALG_AES_ECB_ENC,
                               NULL, 0);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoCipher_init failed with error code %d",
                        __func__, err);
        return err;
    }

    err = OS_CryptoCipher_process(hCipher,
                                  data,
                                  inDataSize,
                                  outBuf,
                                  outDataSize);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoCipher_process failed with error code %d",
                        __func__, err);
    }

    err = OS_CryptoCipher_free(hCipher);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoCipher_free failed with error code %d",
                        __func__, err);
    }

    return err;
}

static OS_Error_t
aesDecrypt(
    OS_Crypto_Handle_t    hCrypto,
    OS_CryptoKey_Handle_t hKey,
    const void*           data,
    size_t                inDataSize,
    void*                 outBuf,
    size_t*               outDataSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    OS_CryptoCipher_Handle_t hCipher;

    *outDataSize = AES_BLOCK_LEN;

    err = OS_CryptoCipher_init(&hCipher, hCrypto, hKey,
                               OS_CryptoCipher_ALG_AES_ECB_DEC,
                               NULL, 0);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoCipher_init failed with error code %d",
                        __func__, err);
        return err;
    }

    err = OS_CryptoCipher_process(hCipher,
                                  data,
                                  inDataSize,
                                  outBuf,
                                  outDataSize);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoCipher_process failed with error code %d",
                        __func__, err);
    }

    err = OS_CryptoCipher_free(hCipher);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoCipher_free failed with error code %d",
                        __func__, err);
    }

    return err;
}
