/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreUnitTests.h"
#include "SeosKeyStoreApi.h"
#include <string.h>
#include "camkes.h"

/* Defines -------------------------------------------------------------------*/
// Various values for the keyStoreUnitTests
#define KEY_NAME            "Key"
#define KEY_NAME_TOO_LARGE  "PrivateKeyPrivateKeyPrivateKeyPrivateKey\0"
#define KEY_NAME_EMPTY      ""
#define KEY_NAME_NOT_THERE  "KeyNotThere"

#define KEY_DATA            "wIoydRkYwMjN1B5KL1YfikL596AFBBRphAUFORLr18AIe6yXlkLutgfpWWGMXWWQczGXmsnc4g9N8HwhmwgjB1cZ8FS3KX8ag8fkK9RopqDOGaiXV2LFJUQKoxB9buFI\0"
#define KEY_DATA_TOO_LARGE  "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\0"
#define KEY_DATA_EMPTY      ""

/* Private functions prototypes ----------------------------------------------*/
static void testImportKey(SeosKeyStoreCtx* keyStoreCtx);
static void testGetKey(SeosKeyStoreCtx* keyStoreCtx);
static void testDeleteKey(SeosKeyStoreCtx* keyStoreCtx);

/* Public functions -----------------------------------------------------------*/
bool keyStoreUnitTests(SeosKeyStoreCtx* keyStoreCtx)
{
    /********************************** TestKeyStore_testCase_01 - 03 ************************************/
    testImportKey(keyStoreCtx);
    testGetKey(keyStoreCtx);
    testDeleteKey(keyStoreCtx);

    return 1;
}

/* Private functions ---------------------------------------------------------*/
static void
testImportKey(SeosKeyStoreCtx* keyStoreCtx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_01 ************************************/
    err = SeosKeyStoreApi_importKey(keyStoreCtx, KEY_NAME, KEY_DATA,
                                    strlen(KEY_DATA));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, KEY_NAME_TOO_LARGE, KEY_DATA,
                                    strlen(KEY_DATA));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_importKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, KEY_NAME_EMPTY, KEY_DATA,
                                    strlen(KEY_DATA));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_importKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, KEY_NAME, KEY_DATA,
                                    strlen(KEY_DATA));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, KEY_NAME, KEY_DATA_TOO_LARGE,
                                    strlen(KEY_DATA_TOO_LARGE));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_importKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, KEY_NAME, KEY_DATA_EMPTY,
                                    strlen(KEY_DATA_EMPTY));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_importKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, NULL, KEY_DATA,
                                    strlen(KEY_DATA_TOO_LARGE));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_importKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_importKey(keyStoreCtx, KEY_NAME_NOT_THERE, NULL,
                                    strlen(KEY_DATA));
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_importKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);
}

static void
testGetKey(SeosKeyStoreCtx* keyStoreCtx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char keyData[128] = {0};
    size_t keySize = sizeof(keyData);

    /********************************** TestKeyStore_testCase_02 ************************************/
    err = SeosKeyStoreApi_getKey(keyStoreCtx, KEY_NAME, keyData, &keySize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_getKey failed with err %d", err);
    Debug_ASSERT_PRINTFLN(keySize == sizeof(keyData),
                          "KeySize after GetKey expected %zu, but is equal %zu", 128, keySize);

    keySize = 0;
    err = SeosKeyStoreApi_getKey(keyStoreCtx, KEY_NAME, keyData, &keySize);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_BUFFER_TOO_SMALL,
                          "SeosKeyStoreApi_importKey supposed to fail with SEOS_ERROR_BUFFER_TOO_SMALL, but returned %d",
                          err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, KEY_NAME_NOT_THERE, keyData,
                                 &keySize);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_importKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, KEY_NAME_EMPTY, keyData, &keySize);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, KEY_NAME_TOO_LARGE, keyData,
                                 &keySize);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, KEY_NAME, NULL, &keySize);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, KEY_NAME, keyData, NULL);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_getKey(keyStoreCtx, NULL, keyData, &keySize);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_getKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);
}

static void
testDeleteKey(SeosKeyStoreCtx* keyStoreCtx)
{
    seos_err_t err = SEOS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_03 ************************************/
    err = SeosKeyStoreApi_deleteKey(keyStoreCtx, KEY_NAME_NOT_THERE);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_FOUND,
                          "SeosKeyStoreApi_deleteKey supposed to fail with SEOS_ERROR_NOT_FOUND, but returned %d",
                          err);

    err = SeosKeyStoreApi_deleteKey(keyStoreCtx, KEY_NAME_TOO_LARGE);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_deleteKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_deleteKey(keyStoreCtx, KEY_NAME_EMPTY);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_deleteKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_deleteKey(keyStoreCtx, NULL);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER,
                          "SeosKeyStoreApi_deleteKey supposed to fail with SEOS_ERROR_INVALID_PARAMETER, but returned %d",
                          err);

    err = SeosKeyStoreApi_deleteKey(keyStoreCtx, KEY_NAME);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_deleteKey failed with err %d", err);
}