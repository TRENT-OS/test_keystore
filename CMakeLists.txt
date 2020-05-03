cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(system_config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_LIBS_LOGGER
    SEOS_CHANMUX
    SEOS_CRYPTO
    SEOS_PARTITION_MANAGER
    SEOS_FILESYSTEM_CORE
    SEOS_FILESYSTEM_FAT
    SEOS_FILESYSTEM_SPIFFS
    SEOS_KEYSTORE
)

set(SEOS_LIBS_KEYSTORE "${SEOS_LIBS_DIR}/seos_keystore")

project(system_config C)
add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR})


project(test_keystore C)

DeclareCAmkESComponent(TopLevelTestRunner
    SOURCES
        components/TopLevelTestRunner/src/topLevelTestRunner.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
)

DeclareCAmkESComponent(TestRunnerKeyStoreFAT
    INCLUDES
        common/init
        common/test
    SOURCES
        common/init/EncryptedPartitionFileStream.c
        common/test/keyStoreUnitTests.c
        common/test/keyStoreIntegrationTests.c
        common/test/keyStoreMultiInstanceTests.c
        components/TestRunnerKeyStoreFAT/src/testRunnerKeystoreFAT.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        system_config
        seos_core_api
        seos_libs
        proxy_nvm
        seos_crypto
        seos_filesystem_fat
        seos_filesystem_spiffs
        seos_partition_manager
        seos_filesystem_core
        seos_keystore
)

DeclareCAmkESComponent(TestRunnerKeyStoreSPIFFS
    INCLUDES
        common/init
        common/test
    SOURCES
        common/init/EncryptedPartitionFileStream.c
        common/test/keyStoreUnitTests.c
        common/test/keyStoreIntegrationTests.c
        common/test/keyStoreMultiInstanceTests.c
        components/TestRunnerKeyStoreSPIFFS/src/TestRunnerKeyStoreSPIFFS.c
    C_FLAGS
        -Wall -Werror
        # filesystem
        -DSEOS_FS_BUILD_AS_LIB
        # partition manager
        -DSEOS_PARTITION_MANAGER_BUILD_AS_LIB
    LIBS
        system_config
        seos_core_api
        seos_libs
        proxy_nvm
        seos_crypto
        seos_filesystem_fat
        seos_filesystem_spiffs
        seos_partition_manager
        seos_filesystem_core
        seos_keystore
)

DeclareCAmkESComponent(UartDrv
    SOURCES
        components/Uart/src/UartDrv.c
        components/Uart/src/qemu_uart.c
    C_FLAGS
        -Wall -Werror
)

DeclareCAmkESComponent(ChanMux
    SOURCES
        components/ChanMux/src/ChanMux.c
    C_FLAGS
        -Wall -Werror
    LIBS
        system_config
        seos_core_api
        chanmux_server
)

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()
