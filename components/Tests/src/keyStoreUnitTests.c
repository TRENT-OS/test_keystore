/**
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "keyStoreUnitTests.h"
#include "OS_Keystore.h"
#include "OS_KeystoreRamFV.h"
#include "OS_KeystoreFile.h"
#include "lib_debug/Debug.h"
#include "lib_macros/Test.h"
#include <string.h>

/* Defines -------------------------------------------------------------------*/
// Various values for the keyStoreUnitTests
#define KEY_SIZE_MAX        2048

#define KEY_NAME            "Key"
#define KEY_NAME_MAX_LEN    "PrivateKey12345"   // strlen is 15
#define KEY_NAME_TOO_LARGE  "PrivateKey123456"  // strlen is 16
#define KEY_NAME_EMPTY      ""
#define KEY_NAME_NOT_THERE  "KeyNotThere"
#define KEY_NAME_MAX_SIZE   "KeyMaxSize"

#define KEY_DATA            "wIoydRkYwMjN1B5KL1YfikL596AFBBRphAUFORLr18AIe6yXlkLutgfpWWGMXWWQczGXmsnc4g9N8HwhmwgjB1cZ8FS3KX8ag8fkK9RopqDOGaiXV2LFJUQKoxB9buFI"
#define KEY_DATA_TOO_LARGE  "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"
#define KEY_DATA_EMPTY      ""

// KEY_DATA_TOO_LARGE must be a string with a length that is one char bigger
// than the maximum key size.
Debug_STATIC_ASSERT(strlen(KEY_DATA_TOO_LARGE) == (KEY_SIZE_MAX + 1));
// Test system relies on the following preconditions
Debug_STATIC_ASSERT(KEY_SIZE_MAX == OS_KeystoreRamFV_MAX_KEY_SIZE);
Debug_STATIC_ASSERT(KEY_SIZE_MAX == OS_KeystoreFile_MAX_KEY_SIZE);

/* Private functions prototypes ----------------------------------------------*/
static void testImportKey(
    OS_Keystore_Handle_t hKeystore);
static void testGetKey(
    OS_Keystore_Handle_t hKeystore);
static void testDeleteKey(
    OS_Keystore_Handle_t hKeystore);
// KeyStoreRamFV dedicated tests
static void
testKeyStoreRamFVSaturation(
    OS_Keystore_Handle_t hKeystore,
    int keyStoreCapacity);

/* Public functions -----------------------------------------------------------*/
void keyStoreUnitTests(
    OS_Keystore_Handle_t hKeystore)
{
    TEST_START();

    testImportKey(hKeystore);
    testGetKey(hKeystore);
    testDeleteKey(hKeystore);

    TEST_FINISH();
}

void keyStoreRamFVUnitTests(
    OS_Keystore_Handle_t hKeystore,
    int keyStoreCapacity)
{
    TEST_START();
    testKeyStoreRamFVSaturation(hKeystore, keyStoreCapacity);
    TEST_FINISH();
}

/* Private functions ---------------------------------------------------------*/
static void
testImportKey(
    OS_Keystore_Handle_t hKeystore)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_01 ************************************/
    // Test storage of a normal key
    err = OS_Keystore_storeKey(hKeystore, KEY_NAME, KEY_DATA,
                               strlen(KEY_DATA));
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    // Test storage of a key whose name length is maximum allowed
    err = OS_Keystore_storeKey(hKeystore, KEY_NAME_MAX_LEN, KEY_DATA,
                               strlen(KEY_DATA));
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    // Test storage of a key whose size is the maximum allowed
    err = OS_Keystore_storeKey(hKeystore, KEY_NAME_MAX_SIZE, KEY_DATA_TOO_LARGE,
                               KEY_SIZE_MAX);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    // Test storage of a key whose name length is maximum allowed
    err = OS_Keystore_storeKey(hKeystore, KEY_NAME_TOO_LARGE, KEY_DATA,
                               strlen(KEY_DATA));
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test storage of a key whose name is empty
    err = OS_Keystore_storeKey(hKeystore, KEY_NAME_EMPTY, KEY_DATA,
                               strlen(KEY_DATA));
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test storage of a key which is already stored
    err = OS_Keystore_storeKey(hKeystore, KEY_NAME, KEY_DATA,
                               strlen(KEY_DATA));
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test storage of a key whose data is too large
    err = OS_Keystore_storeKey(hKeystore, KEY_NAME, KEY_DATA_TOO_LARGE,
                               strlen(KEY_DATA_TOO_LARGE));
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test storage of a key whose data is empty
    err = OS_Keystore_storeKey(hKeystore, KEY_NAME, KEY_DATA_EMPTY,
                               strlen(KEY_DATA_EMPTY));
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test storage of a key whose name is NULL
    err = OS_Keystore_storeKey(hKeystore, NULL, KEY_DATA, strlen(KEY_DATA));
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test storage of a key whose data is NULL and no key is yet stored
    // under that name
    err = OS_Keystore_storeKey(hKeystore, KEY_NAME_NOT_THERE, NULL,
                               strlen(KEY_DATA));
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    TEST_FINISH();
}

static void
testKeyStoreRamFVSaturation(
    OS_Keystore_Handle_t hKeystore,
    int keyStoreCapacity)
{
    char name[sizeof(KEY_NAME) + 11]; // 11 more chars to append '-' and the
                                      // iteration counter (e.g. 'key_name-187')
                                      // number
    int i = 0;
    OS_Error_t err = OS_Keystore_wipeKeystore(hKeystore);

    while (err == OS_SUCCESS && i++ <= keyStoreCapacity)
    {
        sprintf(name, "%s-%d", KEY_NAME, i);
        err = OS_Keystore_storeKey(
            hKeystore,
            name,
            KEY_DATA,
            strlen(KEY_DATA));
    }
    ASSERT_TRUE(OS_ERROR_INSUFFICIENT_SPACE == err);
    ASSERT_EQ_INT(i, keyStoreCapacity + 1);

    OS_Keystore_wipeKeystore(hKeystore);
}

static void
testGetKey(
    OS_Keystore_Handle_t hKeystore)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    static char keyData[KEY_SIZE_MAX] = {0};
    size_t keySize = KEY_SIZE_MAX;

    /********************************** TestKeyStore_testCase_02 ************************************/
    // Test loading of "KEY_NAME" which is already in the key storage
    err = OS_Keystore_loadKey(hKeystore, KEY_NAME, keyData, &keySize);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);
    ASSERT_EQ_SZ(strlen(KEY_DATA), keySize);

    // Test loading of "KEY_NAME_MAX_LEN" which is already in the key storage
    err = OS_Keystore_loadKey(hKeystore, KEY_NAME_MAX_LEN, keyData, &keySize);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);
    ASSERT_EQ_SZ(strlen(KEY_DATA), keySize);

    // Test loading of "KEY_NAME_MAX_SIZE" which is already in the key storage
    keySize = KEY_SIZE_MAX;
    err = OS_Keystore_loadKey(hKeystore, KEY_NAME_MAX_SIZE, keyData, &keySize);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);
    ASSERT_EQ_SZ((size_t)KEY_SIZE_MAX, keySize);

    // Test loading of a key when passing a caller buffer size of 0
    keySize = 0;
    err = OS_Keystore_loadKey(hKeystore, KEY_NAME, keyData, &keySize);
    ASSERT_EQ_OS_ERR(OS_ERROR_BUFFER_TOO_SMALL, err);

    // Test loading of a key which is not there
    err = OS_Keystore_loadKey(hKeystore, KEY_NAME_NOT_THERE, keyData,
                              &keySize);
    ASSERT_EQ_OS_ERR(OS_ERROR_NOT_FOUND, err);

    // Test loading of a key whose name is empty
    err = OS_Keystore_loadKey(hKeystore, KEY_NAME_EMPTY, keyData, &keySize);
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test loading of a key whose name is too large
    err = OS_Keystore_loadKey(hKeystore, KEY_NAME_TOO_LARGE, keyData,
                              &keySize);
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test loading of a key when passing a caller buffer which is NULL
    err = OS_Keystore_loadKey(hKeystore, KEY_NAME, NULL, &keySize);
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test loading of a key when passing a keySize which is NULL
    err = OS_Keystore_loadKey(hKeystore, KEY_NAME, keyData, NULL);
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    // Test loading of a key when passing a caller buffer which is NULL
    err = OS_Keystore_loadKey(hKeystore, NULL, keyData, &keySize);
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);
}

static void
testDeleteKey(
    OS_Keystore_Handle_t hKeystore)
{
    OS_Error_t err = OS_ERROR_GENERIC;

    /********************************** TestKeyStore_testCase_03 ************************************/
    err = OS_Keystore_deleteKey(hKeystore, KEY_NAME_NOT_THERE);
    ASSERT_EQ_OS_ERR(OS_ERROR_NOT_FOUND, err);

    err = OS_Keystore_deleteKey(hKeystore, KEY_NAME_TOO_LARGE);
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    err = OS_Keystore_deleteKey(hKeystore, KEY_NAME_EMPTY);
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    err = OS_Keystore_deleteKey(hKeystore, NULL);
    ASSERT_EQ_OS_ERR(OS_ERROR_INVALID_PARAMETER, err);

    err = OS_Keystore_deleteKey(hKeystore, KEY_NAME);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);

    err = OS_Keystore_deleteKey(hKeystore, KEY_NAME_MAX_LEN);
    ASSERT_EQ_OS_ERR(OS_SUCCESS, err);
}
