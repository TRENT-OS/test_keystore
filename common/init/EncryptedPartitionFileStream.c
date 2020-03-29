/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "system_config.h"
#include "ChanMuxNvmDriver.h"
#include "EncryptedPartitionFileStream.h"

/* FAT defines ---------------------------------------------------------------*/

/* Spiffs defines ------------------------------------------------------------*/
#define SPIFFS_PARTITION_SIZE   (1024*64)
#define SPIFFS_LOG_PAGE_SIZE    256
#define SPIFFS_LOG_BLOCK_SIZE   4096

/* Private variables ---------------------------------------------------------*/


// there can be only one partition manager that connects to an NVM driver. Thus
// the encrypted partition is also a singleton. If multiple instances of
// EncryptedPartitionFileStream are created, they have to share the same
// nvm_driver.

typedef struct {
    void*             dataport;
    uint8_t           channelNum;
    ChanMuxNvmDriver  chanMuxNvm;
} nvm_driver_t;


// we don't need to explicitly store a reference to nvm_driver in the context,
// because it is wrapped in the initialized aesNvm anyway. In the end we access
// everything though the aesNvm only.
typedef struct {
    bool           isInitalized;
    AesNvm         aesNvm;
} ctx_t;


static nvm_driver_t m_nvm_driver;

static ctx_t m_ctx = {
                .isInitalized = false,
};

/* Private functions ---------------------------------------------------------*/

//------------------------------------------------------------------------------
static seos_err_t
nvm_driver_init(
    nvm_driver_t*  nvm_driver,
    bool           doInit,
    uint8_t        channelNum,
    void*          dataport)
{
    if (doInit)
    {
        Debug_LOG_INFO("re-using NVM driver");

        // since we only have one partition manager and NVM stack, there is
        // only  one dataport to ChanMUX. We can't have a different dataport
        // here.
        if (dataport != nvm_driver->dataport)
        {
            Debug_LOG_ERROR("dataport does not match");
            return SEOS_ERROR_GENERIC;
        }

        // since we only have one partition manager and NVM stack, we can't
        // have a different channel here.
        if (channelNum != nvm_driver->channelNum)
        {
            Debug_LOG_ERROR("channel number set to %d, can use different number %d",
                            nvm_driver->channelNum, channelNum);
            return SEOS_ERROR_GENERIC;
        }

        return SEOS_SUCCESS;
    }

    Debug_LOG_INFO("create NVM driver");

    if (!ChanMuxNvmDriver_ctor(
            &(nvm_driver->chanMuxNvm),
            channelNum,
            dataport))
    {
        Debug_LOG_ERROR("ChanMuxNvm_ctor() on Proxy channel %d failed",
                        channelNum);
        return SEOS_ERROR_GENERIC;
    }

    nvm_driver->channelNum   = channelNum;
    nvm_driver->dataport     = dataport;

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
static Nvm*
nvm_driver_get_nvm(
    nvm_driver_t*  nvm_driver)
{
    return ChanMuxNvmDriver_get_nvm( &(nvm_driver->chanMuxNvm) );
}


//------------------------------------------------------------------------------
static seos_err_t
encrypted_partition_init(
    ctx_t*         ctx,
    nvm_driver_t*  nvm_driver)
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
        return SEOS_SUCCESS;
    }

    Debug_LOG_INFO("create AES encrypted NVM and partition manager");

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
            nvm_driver_get_nvm(nvm_driver),
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
    uint8_t                        channelNum,
    uint8_t                        partitionID,
    uint8_t                        fsType,
    void*                          dataport)
{
    seos_err_t ret;

    // There is only one partition manager per task. If multiple instances of
    // EncryptedPartitionFileStream are created, only the first instance
    // initilizes the driver stack, all other instances reuse it. However, this
    // only works is the same parameters are passed, otherwise init will fail.

    // setup the NVM driver (or re-use the instacne that has already been
    // set up)
    ret = nvm_driver_init(
            &m_nvm_driver,
            m_ctx.isInitalized,
            channelNum,
            dataport);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("do_init_nvm_driver() for SPIFFS failed, code %d", ret);
        return ret;
    }

    // setup the encrspted partition (or re-use what has already been set up)
    ret = encrypted_partition_init(&m_ctx, &m_nvm_driver);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("driver_stack_init() failed for channelNum %d, code %d",
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

