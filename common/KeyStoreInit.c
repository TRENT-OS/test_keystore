/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "KeyStoreInit.h"

/* FAT defines -------------------------------------------------------------------*/
#define PARTITION_SIZE      ((32768*2+100) * 512) // for FAT32
#define FORMAT_OPTION       FS_FAT32
#define PARTITION_1         0

/* Spiffs defines -------------------------------------------------------------------*/
#define NVM_PARTITION_SIZE      (1024*128)

/* Public functions -----------------------------------------------------------*/
bool keyStoreContext_ctor(KeyStoreContext*  keyStoreCtx,
                          uint8_t           channelNum,
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

    return true;
}

bool keyStoreContext_dtor(KeyStoreContext* keyStoreCtx)
{
    ChanMuxClient_dtor(&(keyStoreCtx->chanMuxClient));
    ProxyNVM_dtor(ProxyNVM_TO_NVM(&(keyStoreCtx->proxyNVM)));
    AesNvm_dtor(AesNvm_TO_NVM(&(keyStoreCtx->aesNvm)));
    SeosSpiffs_dtor(&(keyStoreCtx->fs));
    FileStreamFactory_dtor(keyStoreCtx->fileStreamFactory);

    return true;
}

int8_t InitFatFS(KeyStoreContext* keyStoreCtx){
    seos_fs_result_t partition_stat = SEOS_FS_SUCCESS;
    seos_pm_result_t pm_stat = SEOS_PM_SUCCESS;
    pm_disk_data_t pm_disk_data;
    pm_partition_data_t pm_partition_data;

    // Preparations
    pm_stat = api_pm_partition_manager_init(&(keyStoreCtx->proxyNVM));
    if(pm_stat != SEOS_PM_SUCCESS)
    {
        Debug_LOG_ERROR("api_pm_partition_manager_init: %d\n", pm_stat);
        return EOF;
    }

    partition_stat = partition_io_layer_partition_init();
    if(partition_stat != SEOS_FS_SUCCESS)
    {
        Debug_LOG_ERROR("Fail to initialize partition!\n");
        return EOF;
    }

    pm_stat = partition_manager_get_info_disk(&pm_disk_data);
    if(pm_stat != SEOS_PM_SUCCESS)
    {
        Debug_LOG_ERROR("Fail to get disk information from partition manager!\n");
        return EOF;
    }


    // Create partitions
    pm_stat = partition_manager_get_info_partition(0, &pm_partition_data);
    if(pm_stat != SEOS_PM_SUCCESS)
    {
        Debug_LOG_ERROR("Fail to get partition information from partition manager!\n");
        return EOF;
    }

    // Register functions
    partition_stat = partition_io_layer_partition_register(pm_partition_data.partition_id, (DISK_IO | FAT), 0);
    if(partition_stat != SEOS_FS_SUCCESS)
    {
        if(partition_stat == SEOS_FS_ERROR_REGISTER)
        {
            Debug_LOG_ERROR("Fail to register io functions!\n");
        }
        return EOF;
    }

    // ... and write the filesystem header in each partition
    partition_stat = partition_io_layer_partition_create_fs(pm_partition_data.partition_id, 
                                                            FORMAT_OPTION, 
                                                            PARTITION_SIZE, /*pm_partition_data.partition_size*/
                                                            0, 
                                                            0, 
                                                            0, 
                                                            0, 
                                                            0, 
                                                            FS_PARTITION_OVERWRITE_CREATE); 
                                                            /* when config a partition size for FAT32, so the size of 
                                                                partition must be min. PARTITION_SIZE but if look in 
                                                                the nvm file, the offset from one partition to the next 
                                                                is two high it will be simulated a FAT32 filesystem, 
                                                                but the real offset in the file is what is defined 
                                                                in main.camkes */
    if(partition_stat != SEOS_FS_SUCCESS)
    {
        Debug_LOG_ERROR("Fail to write FAT filesystem!\n");
        return EOF;
    }

    keyStoreCtx->partition = partition_open(PARTITION_1);
    if(keyStoreCtx->partition == NULL)
    {
        Debug_LOG_ERROR("%s: partition_open failed!", __func__);
        return 0;
    }

    keyStoreCtx->fileStreamFactory = SeosFileStreamFactory_TO_FILE_STREAM_FACTORY(
                                        SeosFileStreamFactory_getInstance(keyStoreCtx->partition));

    return 1;
}

int8_t InitSpifFS(KeyStoreContext* keyStoreCtx)
{
    Debug_ASSERT_PRINTFLN(SeosSpiffs_ctor(&(keyStoreCtx->fs), 
                                            AesNvm_TO_NVM(&(keyStoreCtx->aesNvm)),
                                            NVM_PARTITION_SIZE, 0) == true,
                          "Failed to initialize spiffs!");

    seos_err_t err = SeosSpiffs_mount(&(keyStoreCtx->fs));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "spiffs mount failed with error code %d!", err);

    keyStoreCtx->fileStreamFactory = SpiffsFileStreamFactory_TO_FILE_STREAM_FACTORY(
                                            SpiffsFileStreamFactory_getInstance(&(keyStoreCtx->fs)));

    return 1;
}
