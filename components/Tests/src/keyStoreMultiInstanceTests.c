/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreMultiInstanceTests.h"
#include "OS_Crypto.h"
#include "OS_Keystore.h"
#include "LibDebug/Debug.h"
#include "LibMacros/Test.h"

/* Defines -------------------------------------------------------------------*/
#define COPY_KEY_NAME       "KeyCpy"
#define MOVE_KEY_NAME       "KeyMov"

/* Private variables ---------------------------------------------------------*/
static OS_CryptoKey_Data_t keyData;

static const OS_CryptoKey_Spec_t aes128Spec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS,
    .key = {
        .type = OS_CryptoKey_TYPE_AES,
        .attribs.keepLocal = true,
        .params.bits = 128
    }
};

/* Public functions -----------------------------------------------------------*/
void keyStoreCopyKeyTest(
    OS_Keystore_Handle_t hSrcKeystore,
    OS_Keystore_Handle_t hDstKeystore,
    OS_Crypto_Handle_t   hCrypto)
{
    TEST_START();

    OS_CryptoKey_Handle_t hKey;
    size_t len;
    OS_Error_t err = OS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_12 ************************************/
    err = OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_export(hKey, &keyData);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_storeKey(hSrcKeystore, COPY_KEY_NAME, &keyData,
                               sizeof(keyData));
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_free(hKey);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    /********************************** TestKeyStore_testCase_13 ************************************/
    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hDstKeystore, COPY_KEY_NAME, &keyData, &len);
    ASSERT_EQ_OS_ERR(OS_ERROR_NOT_FOUND, err);

    /********************************** TestKeyStore_testCase_14 ************************************/
    err = OS_Keystore_copyKey(hSrcKeystore, COPY_KEY_NAME, hDstKeystore);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hDstKeystore, COPY_KEY_NAME, &keyData, &len);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    /********************************** Cleanup ************************************/
    err = OS_Keystore_wipeKeystore(hSrcKeystore);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_wipeKeystore(hDstKeystore);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    TEST_FINISH();
}

void keyStoreMoveKeyTest(
    OS_Keystore_Handle_t hSrcKeystore,
    OS_Keystore_Handle_t hDstKeystore,
    OS_Crypto_Handle_t   hCrypto)
{
    TEST_START();

    OS_CryptoKey_Handle_t hKey;
    size_t len;
    OS_Error_t err = OS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_15 ************************************/
    err = OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_export(hKey, &keyData);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_storeKey(hSrcKeystore, MOVE_KEY_NAME, &keyData,
                               sizeof(keyData));
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_free(hKey);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    /********************************** TestKeyStore_testCase_16 ************************************/
    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hDstKeystore, MOVE_KEY_NAME, &keyData, &len);
    ASSERT_EQ_OS_ERR(OS_ERROR_NOT_FOUND, err);

    /********************************** TestKeyStore_testCase_17 ************************************/
    err = OS_Keystore_moveKey(hSrcKeystore, MOVE_KEY_NAME, hDstKeystore);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hSrcKeystore, MOVE_KEY_NAME, &keyData, &len);
    ASSERT_EQ_OS_ERR(OS_ERROR_NOT_FOUND, err);

    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hDstKeystore, MOVE_KEY_NAME, &keyData, &len);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    /********************************** Cleanup ************************************/
    err = OS_Keystore_wipeKeystore(hSrcKeystore);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_wipeKeystore(hDstKeystore);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    TEST_FINISH();
}
