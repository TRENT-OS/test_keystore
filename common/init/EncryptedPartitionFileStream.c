/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */


/* Includes ------------------------------------------------------------------*/
#include "system_config.h"

#include "EncryptedPartitionFileStream.h"

#include "OS_Crypto.h"
#include "LibMem/Nvm.h"
#include "AesNvm.h"
#include "seos_fs.h"
#include "seos_pm_api.h"

#include <stdlib.h>
#include <string.h>


/* FAT defines ---------------------------------------------------------------*/

/* Spiffs defines ------------------------------------------------------------*/
#define SPIFFS_PARTITION_SIZE   (1024*64)
#define SPIFFS_LOG_PAGE_SIZE    256
#define SPIFFS_LOG_BLOCK_SIZE   4096

/* Private variables ---------------------------------------------------------*/

// we explicitly store a reference to the Nvm in the context, because the
// partition manger does not support multiple instance. As a consequence, we
// can't support different instances of Nvm and Crypto in different instances
// of the EncryptedPartitionFileStream. We fail instance creation then.
typedef struct {
    bool                isInitalized;
    Nvm*                nvm;
    OS_Crypto_Handle_t  hCrypto;
    AesNvm              aesNvm;
} ctx_t;


static ctx_t m_ctx = {
                .isInitalized = false,
};

/* Private functions ---------------------------------------------------------*/

//------------------------------------------------------------------------------
static int
entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}


//------------------------------------------------------------------------------
static seos_err_t
encrypted_partition_init(
    ctx_t*          ctx,
    Nvm*            nvm)
{
    seos_err_t ret;

    // Since we can't have multiple instances of the partition manager, the AES
    // encrypted NVM is a singleton also, and as a consequence, we can have a
    // static setup and support one key only. So we don't get key passed as
    // parameter, but have it defined here. Once the partition manager supports
    // multiple instances, we would get key details passed as paramter, as the
    // caller generates ifully independent instances of the keystore
    if (ctx->isInitalized)
    {
        Debug_LOG_INFO("re-using AES encrypted NVM and partition manager");

        if (ctx->nvm != nvm)
        {
            Debug_LOG_ERROR("different nvm instances are not supported");
            return SEOS_ERROR_GENERIC;
        }

        return SEOS_SUCCESS;
    }

    Debug_LOG_INFO("create AES encrypted NVM and partition manager");

    // we create our own crypto instance for convenience reasons. Actually, the
    // caller should pass us one and the whole keystore subsystem should use
    // the same instance everywhere
    static OS_Crypto_Config_t cfgLib =
    {
        .mode = OS_Crypto_MODE_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.lib.rng.entropy = entropy,
    };

    ret = OS_Crypto_init(&(ctx->hCrypto), &cfgLib);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_init failed, code %d", ret);
        return ret;
    }


    static const OS_CryptoKey_Data_t masterKeyData =
    {
        .type = OS_CryptoKey_TYPE_AES,
        .data.aes.len = sizeof(KEYSTORE_KEY_AES)-1,
        .data.aes.bytes = KEYSTORE_KEY_AES
    };

    // initialise the an AES-NVM layer on top of the Proxy-NVM driver. This
    // should actually be part of the keystore already.

    if (!AesNvm_ctor(
            &(ctx->aesNvm),
            nvm,
            ctx->hCrypto,
            KEYSTORE_IV,
            &masterKeyData))
    {
        Debug_LOG_ERROR("AesNvm_ctor() failed");
        return SEOS_ERROR_GENERIC;
    }

    // pass AES NVM driver as NVM layer to partition manager.
    ret = partition_manager_init( AesNvm_TO_NVM( &(ctx->aesNvm) ) );
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("partition_manager_init() failed, code %d",
                        ret);
        return ret;
    }

    ctx->nvm          = nvm;
    ctx->isInitalized = true;

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
// We need this helper function to hide some quirks from the rest of the code
static seos_err_t
do_partition_fs_create(
    hPartition_t          hPartition,
    uint64_t              size,
    uint8_t               fsType)
{
    seos_err_t ret;

    if (fsType <= FS_TYPE_FAT32)
    {
        ret = partition_fs_create(
                hPartition,
                fsType,
                size,
                0,  // default value: size of sector:   512
                0,  // default value: size of cluster:  512
                0,  // default value: reserved sectors count: FAT12/FAT16 = 1; FAT32 = 3
                0,  // default value: count file/dir entries: FAT12/FAT16 = 16; FAT32 = 0
                0,  // default value: count header sectors: 512
                FS_PARTITION_OVERWRITE_CREATE);

        if (ret != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("partition_fs_create() for FAT failed, code %d", ret);
            return ret;
        }
    }
    else
    {
        ret = partition_fs_create(
                hPartition,
                fsType,
                SPIFFS_PARTITION_SIZE,  /* ToDo: why not use size*/
                SPIFFS_LOG_PAGE_SIZE,   /* sector_size, if 0 the default value is used */
                SPIFFS_LOG_BLOCK_SIZE,  /* cluster_size, if 0 the default value is used */
                0,                      /* offset_sectors_count, if 0 the default value is used */
                0,                      /* file_dir_entry_count, if 0 the default value is used */
                0,                      /* fs_header_sector_count, if 0 the default value is used */
                FS_PARTITION_OVERWRITE_CREATE);

        if (ret != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("partition_fs_create() for SPIFFS failed, code %d", ret);
            return ret;
        }
    }

    return SEOS_SUCCESS;
}

//------------------------------------------------------------------------------
static seos_err_t
format_partition(
    EncryptedPartitionFileStream*  self,
    uint8_t                        partitionID,
    uint8_t                        fsType)
{
    seos_err_t ret;

    // check if disk is accessible.
    static pm_disk_data_t pm_disk_data;
    ret = partition_manager_get_info_disk(&pm_disk_data);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("partition_manager_get_info_disk() failed with error code %d",
                        ret);
        return ret;
    }

    pm_partition_data_t pm_partition_data;
    ret = partition_manager_get_info_partition(
            partitionID,
            &pm_partition_data);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("partition_manager_get_info()_partition failed, code %d",
                        ret);
        return ret;
    }

    // sanity check, mthese values should match since we don't support aliasing
    if (partitionID != pm_partition_data.partition_id)
    {
        Debug_LOG_ERROR("partitionID %d does not match pm_partition_data.partition_id %d",
                        partitionID, pm_partition_data.partition_id);
        return SEOS_ERROR_GENERIC;
    }

    // Initialize the partition with RW access
    ret = partition_init(partitionID, 0);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("partition_io_layer_partition_register() failed, code %d",
                        ret);
        return ret;
    }

    hPartition_t hPartition = partition_open(partitionID);
    if (hPartition == NULL)
    {
        Debug_LOG_ERROR("partition_open() failed for ID %d!", partitionID);
        return SEOS_ERROR_GENERIC;
    }

    self->internal.hPartition = hPartition;

    // create a file system in the partition, using the whole sizde
    ret = do_partition_fs_create(
            hPartition,
            pm_partition_data.partition_size,
            fsType);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("do_partition_fs_create() failed, code %d!", ret);
        return ret;
    }

    ret = partition_fs_mount(hPartition);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("partition_fs_mount() failed, code %d", ret);
        return ret;
    }

    Debug_LOG_INFO("Successfully formated and mounted partition ID %d with %s",
                   partitionID,
                   (fsType <= FS_TYPE_FAT32) ? "FAT" : "SPIFFS");

    return SEOS_SUCCESS;
}


/* Public functions ----------------------------------------------------------*/

//------------------------------------------------------------------------------
bool
EncryptedPartitionFileStream_ctor(
    EncryptedPartitionFileStream*  self,
    Nvm*                           nvm,
    uint8_t                        partitionID,
    uint8_t                        fsType)
{
    seos_err_t ret;

    // There is only one partition manager per task. If multiple instances of
    // EncryptedPartitionFileStream are created, only the first instance
    // initilizes the driver stack, all other instances reuse it. However, this
    // only works is the same parameters are passed, otherwise init will fail.

    // setup the encrspted partition (or re-use what has already been set up)
    ret = encrypted_partition_init(&m_ctx, nvm);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("encrypted_partition_init() failed for partition ID %d, code %d",
                        partitionID, ret);
        return false;
    }

    // from now on we really have different independen instances of the
    // EncryptedPartitionFileStream_ctor. Since there is only an implicit
    // global partition manager contenxt that is used automatically, we don't
    // have any paramter that could be passed here as reference
    ret = format_partition(self, partitionID, fsType);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("format_partition() failed for partition ID %d, code %d",
                        partitionID, ret);
        return false;
    }

    if (!SeosFileStreamFactory_ctor(
            &(self->internal.seosFileStreamFactory),
            self->internal.hPartition))
    {
       Debug_LOG_ERROR("SeosFileStreamFactory_ctor() failed");
       return SEOS_ERROR_GENERIC;
    }


    return true;
}


//------------------------------------------------------------------------------
bool
EncryptedPartitionFileStream_dtor(
    EncryptedPartitionFileStream*  self)
{
    // destroy file stream
    FileStreamFactory_dtor(
        EncryptedPartitionFileStream_get_FileStreamFactory(self) );

    // disconnect partition
    partition_fs_unmount(self->internal.hPartition);
    partition_close(self->internal.hPartition);

    // we can't shut down the driver stack, because we don't know how many
    // instances are there. We could have an instance counter to address this,
    // but there is not much gain in the end, because the way how things are
    // currently implemented is more a hack anyway. There is never a real tear
    // down of the instances, but this would be done then:
    //
    //   AesNvm_dtor(AesNvm_TO_NVM(&(m_ctx.aesNvm)));
    //   ChanMuxNvmDriver_dtor(m_nvm_driver)
    //
    // A clean way to implement all this would be passing a nvm_driver and a
    // partition_manager_and_nvm_t object to EncryptedPartitionFileStream_ctor,
    // so we don't care about all this

    return true;
}


//------------------------------------------------------------------------------
FileStreamFactory*
EncryptedPartitionFileStream_get_FileStreamFactory(
    EncryptedPartitionFileStream*  self)
{
    return SeosFileStreamFactory_TO_FILE_STREAM_FACTORY(
            &(self->internal.seosFileStreamFactory) );
}

