/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreMultiInstanceTests.h"
#include "OS_Crypto.h"
#include "OS_Keystore.h"
#include "LibDebug/Debug.h"

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
        .attribs.exportable = true,
        .params.bits = 128
    }
};

/* Public functions -----------------------------------------------------------*/
bool keyStoreCopyKeyTest(
    OS_Keystore_Handle_t hSrcKeystore,
    OS_Keystore_Handle_t hDstKeystore,
    OS_Crypto_Handle_t   hCrypto)
{
    OS_CryptoKey_Handle_t hKey;
    size_t len;
    OS_Error_t err = OS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_12 ************************************/
    err = OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_generate failed with err %d", err);

    err = OS_CryptoKey_export(hKey, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_export failed with err %d", err);

    err = OS_Keystore_storeKey(hSrcKeystore, COPY_KEY_NAME, &keyData,
                               sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_storeKey failed with err %d", err);

    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    /********************************** TestKeyStore_testCase_13 ************************************/
    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hDstKeystore, COPY_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == OS_ERROR_NOT_FOUND,
                          "OS_Keystore_loadKey supposed to fail with OS_ERROR_NOT_FOUND, but returned %d",
                          err);

    /********************************** TestKeyStore_testCase_14 ************************************/
    err = OS_Keystore_copyKey(hSrcKeystore, COPY_KEY_NAME, hDstKeystore);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_copyKey failed with err %d", err);

    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hDstKeystore, COPY_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_loadKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);

    /********************************** Cleanup ************************************/
    err = OS_Keystore_wipeKeystore(hSrcKeystore);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_wipeKeystore failed with err %d", err);

    err = OS_Keystore_wipeKeystore(hDstKeystore);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_wipeKeystore failed with err %d", err);

    return true;
}

bool keyStoreMoveKeyTest(
    OS_Keystore_Handle_t hSrcKeystore,
    OS_Keystore_Handle_t hDstKeystore,
    OS_Crypto_Handle_t   hCrypto)
{
    OS_CryptoKey_Handle_t hKey;
    size_t len;
    OS_Error_t err = OS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_15 ************************************/
    err = OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_generate failed with err %d", err);

    err = OS_CryptoKey_export(hKey, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_export failed with err %d", err);

    err = OS_Keystore_storeKey(hSrcKeystore, MOVE_KEY_NAME, &keyData,
                               sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_storeKey failed with err %d", err);

    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    /********************************** TestKeyStore_testCase_16 ************************************/
    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hDstKeystore, MOVE_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == OS_ERROR_NOT_FOUND,
                          "OS_Keystore_loadKey supposed to fail with OS_ERROR_NOT_FOUND, but returned %d",
                          err);

    /********************************** TestKeyStore_testCase_17 ************************************/
    err = OS_Keystore_moveKey(hSrcKeystore, MOVE_KEY_NAME, hDstKeystore);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_moveKey failed with err %d", err);

    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hSrcKeystore, MOVE_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == OS_ERROR_NOT_FOUND,
                          "OS_Keystore_loadKey supposed to fail with OS_ERROR_NOT_FOUND, but returned %d",
                          err);

    len = sizeof(keyData);
    err = OS_Keystore_loadKey(hDstKeystore, MOVE_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_loadKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);

    /********************************** Cleanup ************************************/
    err = OS_Keystore_wipeKeystore(hSrcKeystore);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_wipeKeystore failed with err %d", err);

    err = OS_Keystore_wipeKeystore(hDstKeystore);
    Debug_ASSERT_PRINTFLN(err == OS_SUCCESS,
                          "OS_Keystore_wipeKeystore failed with err %d", err);

    return true;
}
