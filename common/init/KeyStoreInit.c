/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "KeyStoreInit.h"

/* FAT defines -------------------------------------------------------------------*/

/* Spiffs defines -------------------------------------------------------------------*/
#define SPIFFS_PARTITION_SIZE   (1024*64)
#define SPIFFS_LOG_PAGE_SIZE    256
#define SPIFFS_LOG_BLOCK_SIZE   4096

/* Private function prototypes -----------------------------------------------------------*/
static seos_err_t InitFS(KeyStoreContext* keyStoreCtx, uint8_t partitionID, uint8_t fsType);
static seos_err_t preparePartitionManager(KeyStoreContext* keyStoreCtx);

/* Private variables -----------------------------------------------------------*/
static pm_disk_data_t pm_disk_data;
static bool pmInitalized = false;

static char proxyBuffer[PAGE_SIZE];

/* Public functions -----------------------------------------------------------*/
bool keyStoreContext_ctor(KeyStoreContext*  keyStoreCtx,
                          uint8_t           channelNum,
                          uint8_t           partitionID,
                          uint8_t           fsType,
                          void*             dataport)
{
    if (!ChanMuxClient_ctor(&(keyStoreCtx->chanMuxClient),
                            channelNum,
                            dataport,
                            dataport))
    {
        Debug_LOG_ERROR("%s: Failed to construct chanMuxClient, channel %d!", __func__,
                        channelNum);
        return false;
    }

    if (!ProxyNVM_ctor(&(keyStoreCtx->proxyNVM), &(keyStoreCtx->chanMuxClient),
                       proxyBuffer, PAGE_SIZE))
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
    partition_fs_unmount(keyStoreCtx->partition);
    partition_close(keyStoreCtx->partition);

    ChanMuxClient_dtor(&(keyStoreCtx->chanMuxClient));
    ProxyNVM_dtor(ProxyNVM_TO_NVM(&(keyStoreCtx->proxyNVM)));
    AesNvm_dtor(AesNvm_TO_NVM(&(keyStoreCtx->aesNvm)));
    FileStreamFactory_dtor(SeosFileStreamFactory_TO_FILE_STREAM_FACTORY(&(keyStoreCtx->fileStreamFactory)));

    return true;
}

static seos_err_t InitFS(KeyStoreContext* keyStoreCtx, uint8_t partitionID, uint8_t fsType)
{
    seos_fs_result_t fs_stat;
    seos_pm_result_t pm_stat;
    pm_partition_data_t pm_partition_data;
    seos_err_t ret;

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

    fs_stat = partition_init(pm_partition_data.partition_id, 0);
    Debug_ASSERT_PRINTFLN(fs_stat == SEOS_FS_SUCCESS,
                            "partition_io_layer_partition_register failed with err %d", fs_stat);

    keyStoreCtx->partition = partition_open(partitionID);
    if(keyStoreCtx->partition == NULL)
    {
        Debug_LOG_ERROR("partition_open failed!");
        return SEOS_ERROR_ABORTED;
    }

    // ... and write the filesystem header in each partition
    if(fsType <= FS_TYPE_FAT32)
    {
        fs_stat = partition_fs_create(
                    keyStoreCtx->partition,
                    fsType,
                    pm_partition_data.partition_size,
                    0,  // default value: size of sector:   512
                    0,  // default value: size of cluster:  512
                    0,  // default value: reserved sectors count: FAT12/FAT16 = 1; FAT32 = 3
                    0,  // default value: count file/dir entries: FAT12/FAT16 = 16; FAT32 = 0
                    0,  // default value: count header sectors: 512
                    FS_PARTITION_OVERWRITE_CREATE);
        Debug_ASSERT_PRINTFLN(fs_stat == SEOS_FS_SUCCESS,
                                "Fail to write FAT filesystem! err %d", fs_stat);
    }
    else
    {
        fs_stat = partition_fs_create(
                    keyStoreCtx->partition,
                    fsType,
                    SPIFFS_PARTITION_SIZE,  /*pm_partition_data.partition_size*/
                    SPIFFS_LOG_PAGE_SIZE,   /* sector_size, if 0 the default value is used */
                    SPIFFS_LOG_BLOCK_SIZE,  /* cluster_size, if 0 the default value is used */
                    0,                      /* offset_sectors_count, if 0 the default value is used */
                    0,                      /* file_dir_entry_count, if 0 the default value is used */
                    0,                      /* fs_header_sector_count, if 0 the default value is used */
                    FS_PARTITION_OVERWRITE_CREATE);
        Debug_ASSERT_PRINTFLN(fs_stat == SEOS_FS_SUCCESS,
                                "Fail to write SPIFFS filesystem! err %d", fs_stat);
    }

    fs_stat = partition_fs_mount(keyStoreCtx->partition);
    Debug_ASSERT_PRINTFLN(fs_stat == SEOS_FS_SUCCESS,
                            "Fail to mount filesystem: %d!", partitionID);

    if(fsType <= FS_TYPE_FAT32)
    {
        Debug_LOG_DEBUG("Successfully mounted FAT_FS!");
    }
    else
    {
        Debug_LOG_DEBUG("Successfully mounted SPIF_FS!");
    }

    if(!SeosFileStreamFactory_ctor(&(keyStoreCtx->fileStreamFactory), keyStoreCtx->partition))
    {
       Debug_LOG_ERROR("failed to instantiate the filestream factory!");
       return SEOS_ERROR_ABORTED;
    }

    return SEOS_SUCCESS;
}

static seos_err_t preparePartitionManager(KeyStoreContext* keyStoreCtx)
{
    seos_pm_result_t pm_stat;

    pm_stat = partition_manager_init(&(keyStoreCtx->aesNvm));
    if(pm_stat != SEOS_PM_SUCCESS)
    {
        Debug_LOG_ERROR("api_pm_partition_manager_init failed with error code %d\n", pm_stat);
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
