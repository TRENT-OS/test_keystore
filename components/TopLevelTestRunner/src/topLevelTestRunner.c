/**
 * @addtogroup KeyStore_Tests
 * @{
 *
 * @file topLevelTestRunner.c
 *
 * @brief   Entry point of the Test_KeyStore system 
 *          that contains the top level test runner
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#include "camkes.h"

/**
 * @weakgroup KeyStore_top_level
 * @{
 *
 * @brief   Top level test runner that executes test runs
 *          for the keystores based on top of the FAT and SPIFFS
 *          filesystems
 *
 * @}
 */
int run()
{
    testRunnerKeyStoreFatInf_runTests();
    //testRunnerKeyStoreSpiffsInf_runTests();

    return 0;
}

///@}
