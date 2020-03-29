/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "LibDebug/Debug.h"

#include "KeyStoreFAT.h"
#include "EncryptedPartitionFileStream.h"

#include "OS_Crypto.h"

#include <camkes.h>

/* Private function prototypes ------------------------------------------------*/
static int entropyFunc(void* ctx, unsigned char* buf, size_t len);

/* Public variables -----------------------------------------------------------*/
static OS_Crypto_Handle_t hCrypto;

/* Public functions -----------------------------------------------------------*/

OS_Crypto_Handle_t
OS_CryptoRpcServer_getCrypto(
    void)
{
    // We have only a single instance
    return hCrypto;
}

// Public Functions -----------------------------------------------------------

seos_err_t
CryptoRpcServer_openSession(
    void)
{
    seos_err_t err;
    OS_Crypto_Config_t cfg =
    {
        .mode = OS_Crypto_MODE_RPC_SERVER_WITH_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free   = free,
        },
        .impl.lib.rng = {
            .entropy = entropyFunc,
        },
        .server.dataPort = cryptoServerDataport
    };

    if ((err = OS_Crypto_init(&hCrypto, &cfg)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_init failed with %d", err);
    }

    return err;
}

seos_err_t
CryptoRpcServer_closeSession(
    void)
{
    seos_err_t err;

    if ((err = OS_Crypto_free(hCrypto)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_free failed with %d", err);
    }

    return err;
}

seos_err_t
KeyStore_getRpcHandle(SeosKeyStoreRpc_Handle* instance)
{
    static SeosKeyStore keyStore;
    static SeosKeyStoreRpc the_one;
    static EncryptedPartitionFileStream encryptedPartitionFileStream;

    seos_err_t retval;


    Debug_LOG_INFO("create EncryptedPartitionFileStream for channel %d, partition ID %d",
                   NVM_CHANNEL_NUMBER, KEY_STORE_FAT_INSTANCE_1_PARTITION);

    if (!EncryptedPartitionFileStream_ctor(
            &encryptedPartitionFileStream,
            NVM_CHANNEL_NUMBER,
            KEY_STORE_FAT_INSTANCE_1_PARTITION,
            FS_TYPE_FAT32,
            chanMuxDataPort))
    {
        Debug_LOG_ERROR("%s: Failed to initialize the test!", __func__);
        return 0;
    }

    retval = SeosKeyStore_init(
                &keyStore,
                EncryptedPartitionFileStream_get_FileStreamFactory(
                    &encryptedPartitionFileStream ),
                hCrypto,
                KEY_STORE_FAT_INSTANCE_1_NAME);

    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStore_init failed with error code %d!", __func__,
                        retval);
        return retval;
    }

    retval = SeosKeyStoreRpc_init(
                &the_one,
                &(keyStore.parent),
                keyStoreServerDataport);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_init failed with error code %d!", __func__,
                        retval);
        return retval;
    }

    *instance = &the_one;

    if (SEOS_SUCCESS == retval)
    {
        Debug_LOG_TRACE("%s: created rpc object %p", __func__, *instance);
    }

    return retval;
}

void
KeyStore_closeRpcHandle(SeosKeyStoreRpc_Handle instance)
{
    /// TODO
}

/* Private functios -----------------------------------------------------------*/
static int entropyFunc(void*           ctx,
                unsigned char*  buf,
                size_t          len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}
