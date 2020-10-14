#
# Test Keystore
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(system_config.h)


#-------------------------------------------------------------------------------
project(system_config C)
add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR})


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
        os_libs
        os_keystore
        os_filesystem
        os_crypto
)

DeclareCAmkESComponent_EntropySource(
    EntropySource
)

DeclareCAmkESComponent_RamDisk(
    RamDisk
    system_config
)

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
