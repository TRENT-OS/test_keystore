/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreMultiInstanceTests.h"
#include "OS_Crypto.h"
#include "SeosKeyStoreApi.h"
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
bool keyStoreCopyKeyTest(SeosKeyStoreCtx* srcKeyStore, SeosKeyStoreCtx* dstKeyStore, OS_Crypto_Handle_t hCrypto)
{
    OS_CryptoKey_Handle_t hKey;
    size_t len;
    seos_err_t err = SEOS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_12 ************************************/
    err = OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_generate failed with err %d", err);

    err = OS_CryptoKey_export(hKey, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_export failed with err %d", err);

    err = SeosKeyStoreApi_importKey(srcKeyStore, COPY_KEY_NAME, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    /********************************** TestKeyStore_testCase_13 ************************************/
    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(dstKeyStore, COPY_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d", err);

    /********************************** TestKeyStore_testCase_14 ************************************/
    err = SeosKeyStoreApi_copyKey(srcKeyStore, COPY_KEY_NAME, dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_copyKey failed with err %d", err);

    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(dstKeyStore, COPY_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);

    /********************************** Cleanup ************************************/
    err = SeosKeyStoreApi_wipeKeyStore(srcKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    err = SeosKeyStoreApi_wipeKeyStore(dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    return true;
}

bool keyStoreMoveKeyTest(SeosKeyStoreCtx* srcKeyStore, SeosKeyStoreCtx* dstKeyStore, OS_Crypto_Handle_t hCrypto)
{
    OS_CryptoKey_Handle_t hKey;
    size_t len;
    seos_err_t err = SEOS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_15 ************************************/
    err = OS_CryptoKey_generate(&hKey, hCrypto, &aes128Spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_generate failed with err %d", err);

    err = OS_CryptoKey_export(hKey, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_export failed with err %d", err);

    err = SeosKeyStoreApi_importKey(srcKeyStore, MOVE_KEY_NAME, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = OS_CryptoKey_free(hKey);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_free failed with err %d", err);

    /********************************** TestKeyStore_testCase_16 ************************************/
    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(dstKeyStore, MOVE_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d", err);

    /********************************** TestKeyStore_testCase_17 ************************************/
    err = SeosKeyStoreApi_moveKey(srcKeyStore, MOVE_KEY_NAME, dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_moveKey failed with err %d", err);

    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(srcKeyStore, MOVE_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d", err);

    len = sizeof(keyData);
    err = SeosKeyStoreApi_getKey(dstKeyStore, MOVE_KEY_NAME, &keyData, &len);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);

    err = OS_CryptoKey_import(&hKey, hCrypto, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_import failed with err %d", err);

    /********************************** Cleanup ************************************/
    err = SeosKeyStoreApi_wipeKeyStore(srcKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    err = SeosKeyStoreApi_wipeKeyStore(dstKeyStore);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_wipeKeyStore failed with err %d", err);

    return true;
}
