/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "KeyStoreInit.h"

/* FAT defines -------------------------------------------------------------------*/
/*  This is the minimum value of the partition for FAT_32
    formatting required by the library, but this does not
    actually represent the partition size in the current
    architecture (since we depend on the size of the memory
    file in the mqtt_proxy application), but the real value
    of the partition is defined in the KeyStoreTestTopLevel.camkes
    in the configuration block */
#define FAT_PARTITION_SIZE      ((32768*2+100) * 512)
#define FAT_FORMAT_OPTION       FS_FAT32

/* Spiffs defines -------------------------------------------------------------------*/
#define SPIFFS_PARTITION_SIZE   (1024*64)
#define SPIFFS_FORMAT_OPTION    FS_SPIF
#define SPIFFS_LOG_PAGE_SIZE    256
#define SPIFFS_LOG_BLOCK_SIZE   4096

/* Private function prototypes -----------------------------------------------------------*/
static seos_err_t InitFS(KeyStoreContext* keyStoreCtx, uint8_t partitionID, register_fs_t fsType);
static seos_err_t preparePartitionManager(KeyStoreContext* keyStoreCtx);

/* Private variables -----------------------------------------------------------*/
static pm_disk_data_t pm_disk_data;
static bool pmInitalized = false;

/* Public functions -----------------------------------------------------------*/
bool keyStoreContext_ctor(KeyStoreContext*  keyStoreCtx,
                          uint8_t           channelNum,
                          uint8_t           partitionID,
                          register_fs_t     fsType,
                          void*             dataport)
{
    if (!ChanMuxClient_ctor(&(keyStoreCtx->chanMuxClient), channelNum, dataport))
    {
        Debug_LOG_ERROR("%s: Failed to construct chanMuxClient, channel %d!", __func__,
                        channelNum);
        return false;
    }

    if (!ProxyNVM_ctor(&(keyStoreCtx->proxyNVM), &(keyStoreCtx->chanMuxClient),
                       dataport, PAGE_SIZE))
    {
        Debug_LOG_ERROR("%s: Failed to construct proxyNVM, channel %d!", __func__,
                        channelNum);
        return false;
    }

    if (!AesNvm_ctor(&(keyStoreCtx->aesNvm),
                     ProxyNVM_TO_NVM(&(keyStoreCtx->proxyNVM))))
    {
        Debug_LOG_ERROR("%s: Failed to initialize AesNvm, channel %d!", __func__,
                        channelNum);
        return false;
    }

    seos_err_t err = InitFS(keyStoreCtx, partitionID, fsType);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                            "Failed to initialize the filesystem! err %d", err);

    return true;
}

bool keyStoreContext_dtor(KeyStoreContext* keyStoreCtx)
{
    ChanMuxClient_dtor(&(keyStoreCtx->chanMuxClient));
    ProxyNVM_dtor(ProxyNVM_TO_NVM(&(keyStoreCtx->proxyNVM)));
    AesNvm_dtor(AesNvm_TO_NVM(&(keyStoreCtx->aesNvm)));
    FileStreamFactory_dtor(SeosFileStreamFactory_TO_FILE_STREAM_FACTORY(&(keyStoreCtx->fileStreamFactory)));

    return true;
}

static seos_err_t InitFS(KeyStoreContext* keyStoreCtx, uint8_t partitionID, register_fs_t fsType)
{
    seos_fs_result_t partition_stat = SEOS_FS_SUCCESS;
    seos_pm_result_t pm_stat = SEOS_PM_SUCCESS;
    pm_partition_data_t pm_partition_data;
    seos_err_t ret = SEOS_ERROR_GENERIC;

    if(!pmInitalized)
    {
        ret = preparePartitionManager(keyStoreCtx);
        Debug_ASSERT_PRINTFLN(ret == SEOS_SUCCESS,
                            "preparePartitionManager failed with err %d", ret);
    }

    // Create partitions
    pm_stat = partition_manager_get_info_partition(partitionID, &pm_partition_data);
    Debug_ASSERT_PRINTFLN(pm_stat == SEOS_PM_SUCCESS,
                            "partition_manager_get_info_partition failed with err %d", pm_stat);

    // Register functions
    partition_stat = partition_io_layer_partition_register(pm_partition_data.partition_id, (DISK_IO | fsType), 0);
    Debug_ASSERT_PRINTFLN(partition_stat == SEOS_FS_SUCCESS,
                            "partition_io_layer_partition_register failed with err %d", partition_stat);

    // ... and write the filesystem header in each partition
    if(fsType == SEOS_FS_TYPE_FAT)
    {
        partition_stat = partition_io_layer_partition_create_fs(
                            pm_partition_data.partition_id, 
                            FAT_FORMAT_OPTION, 
                            FAT_PARTITION_SIZE, /*pm_partition_data.partition_size*/
                            0,                  /* sector_size, if 0 the default value is used */
                            0,                  /* cluster_size, if 0 the default value is used */
                            0,                  /* offset_sectors_count, if 0 the default value is used */
                            0,                  /* file_dir_entry_count, if 0 the default value is used */
                            0,                  /* fs_header_sector_count, if 0 the default value is used */
                            FS_PARTITION_OVERWRITE_CREATE);
        Debug_ASSERT_PRINTFLN(partition_stat == SEOS_FS_SUCCESS,
                                "Fail to write FAT filesystem! err %d", partition_stat);
    }
    else
    {
        partition_stat = partition_io_layer_partition_create_fs(
                            pm_partition_data.partition_id, 
                            SPIFFS_FORMAT_OPTION, 
                            SPIFFS_PARTITION_SIZE,  /*pm_partition_data.partition_size*/
                            SPIFFS_LOG_PAGE_SIZE,   /* sector_size, if 0 the default value is used */
                            SPIFFS_LOG_BLOCK_SIZE,  /* cluster_size, if 0 the default value is used */
                            0,                      /* offset_sectors_count, if 0 the default value is used */
                            0,                      /* file_dir_entry_count, if 0 the default value is used */
                            0,                      /* fs_header_sector_count, if 0 the default value is used */
                            FS_PARTITION_OVERWRITE_CREATE);
        Debug_ASSERT_PRINTFLN(partition_stat == SEOS_FS_SUCCESS,
                                "Fail to write SPIFFS filesystem! err %d", partition_stat);
    }

    keyStoreCtx->partition = partition_open(partitionID);
    if(keyStoreCtx->partition == NULL)
    {
        Debug_LOG_ERROR("%s: partition_open failed!", __func__);
        return SEOS_ERROR_ABORTED;
    }

    if(fsType == SEOS_FS_TYPE_FAT)
    {
        Debug_LOG_DEBUG("%s: Successfully mounted FAT_FS!", __func__);
    }
    else
    {
        Debug_LOG_DEBUG("%s: Successfully mounted SPIF_FS!", __func__);
    }

    if(!SeosFileStreamFactory_ctor(&(keyStoreCtx->fileStreamFactory), keyStoreCtx->partition))
    {
       Debug_LOG_ERROR("%s: failed to instantiate the filestream factory!", __func__);
       return SEOS_ERROR_ABORTED;
    }

    return SEOS_SUCCESS;
}

static seos_err_t preparePartitionManager(KeyStoreContext* keyStoreCtx)
{
    seos_pm_result_t pm_stat = SEOS_PM_SUCCESS;
    seos_fs_result_t partition_stat = SEOS_FS_SUCCESS;

    pm_stat = api_pm_partition_manager_init(&(keyStoreCtx->aesNvm));
    if(pm_stat != SEOS_PM_SUCCESS)
    {
        Debug_LOG_ERROR("api_pm_partition_manager_init failed with error code %d\n", pm_stat);
        return SEOS_ERROR_ABORTED;
    }

    partition_stat = partition_io_layer_partition_init();
    if(partition_stat != SEOS_FS_SUCCESS)
    {
        Debug_LOG_ERROR("partition_io_layer_partition_init failed with error code %d\n", pm_stat);
        return SEOS_ERROR_ABORTED;
    }

    pm_stat = partition_manager_get_info_disk(&pm_disk_data);
    if(pm_stat != SEOS_PM_SUCCESS)
    {
        Debug_LOG_ERROR("partition_manager_get_info_disk failed with error code %d\n", pm_stat);
        return SEOS_ERROR_ABORTED;
    }

    pmInitalized = true;

    return SEOS_SUCCESS;
}
