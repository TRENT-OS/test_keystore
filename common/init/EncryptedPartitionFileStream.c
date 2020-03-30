/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "config.h"
#include "EncryptedPartitionFileStream.h"

/* FAT defines ---------------------------------------------------------------*/

/* Spiffs defines ------------------------------------------------------------*/
#define SPIFFS_PARTITION_SIZE   (1024*64)
#define SPIFFS_LOG_PAGE_SIZE    256
#define SPIFFS_LOG_BLOCK_SIZE   4096

/* Private variables ---------------------------------------------------------*/

// there can be only one partition manager that connects to an NVM driver stack
// which does the partition encryption. If multiple instances of
// EncryptedPartitionFileStream are created, they also have to share this.
typedef struct {
    bool            isInitalized;

    ChanMuxClient   chanMuxClient;
    void*           dataport;
    uint8_t         channelNum;

    ProxyNVM        proxyNVM;
    char            proxyBuffer[PAGE_SIZE];

    AesNvm          aesNvm;
} partition_manager_and_nvm_t;


static partition_manager_and_nvm_t partition_manager_and_nvm = {
    .isInitalized = false
};

/* Private functions ---------------------------------------------------------*/

//------------------------------------------------------------------------------
static seos_err_t
init_NVM_driver(
    uint8_t  channelNum,
    void*    dataport)
{
    // there is no partition manager component in the system, we connect
    // directly to a NVM channel of ChanMUX. Since the NVM protocol is based on
    // synchronuous request and response commands, we don't need a full duplex
    // capabilites and can use the same data port for both directions.
    if (!ChanMuxClient_ctor(
            &(partition_manager_and_nvm.chanMuxClient),
            channelNum,
            dataport,
            dataport))
    {
        Debug_LOG_ERROR("ChanMuxClient_ctor() failed for channel %d",
                        channelNum);
        return SEOS_ERROR_GENERIC;
    }

    // initialise the Proxy-NVM driver library.
    if (!ProxyNVM_ctor(
            &(partition_manager_and_nvm.proxyNVM),
            &(partition_manager_and_nvm.chanMuxClient),
            partition_manager_and_nvm.proxyBuffer,
            sizeof(partition_manager_and_nvm.proxyBuffer)))
    {
        Debug_LOG_ERROR("ProxyNVM_ctor() failed");
        return SEOS_ERROR_GENERIC;
    }

    static const OS_CryptoKey_Data_t masterKeyData =
    {
        .type = OS_CryptoKey_TYPE_AES,
        .data.aes.len = sizeof(KEYSTORE_KEY_AES)-1,
        .data.aes.bytes = KEYSTORE_KEY_AES
    };

    // initialise the an AES-NVM layer on top of the Proxy-NVM driver
    if (!AesNvm_ctor(
            &(partition_manager_and_nvm.aesNvm),
            ProxyNVM_TO_NVM(&(partition_manager_and_nvm.proxyNVM)),
            KEYSTORE_IV,
            &masterKeyData))
    {
        Debug_LOG_ERROR("AesNvm_ctor() failed");
        return SEOS_ERROR_GENERIC;
    }

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

    self->internal.hPartition = partition_open(partitionID);
    if (self->internal.hPartition == NULL)
    {
        Debug_LOG_ERROR("partition_open() failed for ID %d!", partitionID);
        return SEOS_ERROR_GENERIC;
    }

    // create a file system in the partition, using the whole sizde
    ret = do_partition_fs_create(
            self->internal.hPartition,
            pm_partition_data.partition_size,
            fsType);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("do_partition_fs_create() failed, code %d!", ret);
        return ret;
    }

    ret = partition_fs_mount(self->internal.hPartition);
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
    // EncryptedPartitionFileStream are create only the first instance
    // initilizes the partition manager lib.
    if(partition_manager_and_nvm.isInitalized)
    {
        Debug_LOG_INFO("re-using partition manager and NVM driver");

        // since we only have one partition manager and NVM stack, there is
        // only  one dataport to ChanMUX. We can't have a different dataport
        // here.
        if (dataport != partition_manager_and_nvm.dataport)
        {
            Debug_LOG_ERROR("dataport does not match");
            return false;
        }

        // since we only have one partition manager and NVM stack, we can't
        // have a different channel here.
        if (channelNum != partition_manager_and_nvm.channelNum)
        {
            Debug_LOG_ERROR("channel number set to %d, can use different number %d",
                             partition_manager_and_nvm.channelNum, channelNum);
            return false;
        }

    }
    else
    {
        Debug_LOG_INFO("create partition manager and NVM driver");

        ret = init_NVM_driver(channelNum, dataport);
        if (ret != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("init_NVM_driver() on Proxy channel %d failed, code %d",
                        channelNum, ret);
            return false;
        }

        // pass actual NVM driver to partition manager. The driver is the AES
        // NVM layer.
        ret = partition_manager_init(&(partition_manager_and_nvm.aesNvm));
        if (ret != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("api_pm_partition_manager_init() failed, code %d",
                            ret);
            return ret;
        }
        partition_manager_and_nvm.channelNum   = channelNum;
        partition_manager_and_nvm.dataport     = dataport;
        partition_manager_and_nvm.isInitalized = true;
    }

    ret = format_partition(self, partitionID, fsType);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("format_partition() failed fror partition ID %d , code %d",
                        partitionID, ret);
        return false;
    }

    if (!SeosFileStreamFactory_ctor(
            &(self->fileStreamFactory),
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
    // descroty file stream
    FileStreamFactory_dtor(
        SeosFileStreamFactory_TO_FILE_STREAM_FACTORY(
            &(self->fileStreamFactory) ) );

    // disconnect partition
    partition_fs_unmount(self->internal.hPartition);
    partition_close(self->internal.hPartition);

    // we can't shut down the driver stack, because we don't know how many
    // instances are there. We could have an instance counter to address this,
    // but the way how things are currently implemented is more a hack anyway.
    // One should create a partition_manager_and_nvm_t object and then  pass it
    // to EncryptedPartitionFileStream_ctor, so we don't care about all this
    // here.
    //
    // ChanMuxClient_dtor(&(partition_manager_and_nvm.chanMuxClient));
    // ProxyNVM_dtor(ProxyNVM_TO_NVM(&(partition_manager_and_nvm.proxyNVM)));
    // AesNvm_dtor(AesNvm_TO_NVM(&(partition_manager_and_nvm.aesNvm)));

    return true;
}
