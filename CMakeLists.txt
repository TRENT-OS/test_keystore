#
# Test Keystore
#
# Copyright (C) 2020-2024, HENSOLDT Cyber GmbH
# 
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For commercial licensing, contact: info.cyber@hensoldt.net
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
# use the SDK
find_package("os-sdk" REQUIRED)
os_sdk_set_defaults()
os_sdk_setup(CONFIG_FILE "system_config.h" CONFIG_PROJECT "system_config")


#-------------------------------------------------------------------------------
project(test_keystore C)

DeclareCAmkESComponent(
    test_OS_Keystore
    INCLUDES
        components/Tests/include
    SOURCES
        components/Tests/src/test_OS_Keystore.c
        components/Tests/src/keyStoreUnitTests.c
        components/Tests/src/keyStoreIntegrationTests.c
        components/Tests/src/keyStoreMultiInstanceTests.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        lib_debug
        lib_macros
        os_keystore_file
        os_keystore_ram_fv
        os_filesystem
        os_crypto
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

RamDisk_DeclareCAmkESComponent(
    RamDisk
)

os_sdk_create_CAmkES_system("main.camkes")
