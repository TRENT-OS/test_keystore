cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(system_config.h)

os_use_libs(
    OS_LIBS
    OS_LIBS_LOGGER
    OS_CHANMUX
    OS_CRYPTO
    OS_PARTITION_MANAGER
    OS_FILESYSTEM_CORE
    OS_FILESYSTEM_FAT
    OS_FILESYSTEM_SPIFFS
    OS_KEYSTORE
)

set(OS_LIBS_KEYSTORE "${OS_LIBS_DIR}/seos_keystore")

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
        -DOS_FS_BUILD_AS_LIB
        # partition manager
        -DOS_PARTITION_MANAGER_BUILD_AS_LIB
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
        -DOS_FS_BUILD_AS_LIB
        # partition manager
        -DOS_PARTITION_MANAGER_BUILD_AS_LIB
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

DeclareCAmkESComponent_UART(
    UART
)

DeclareCAmkESComponent_ChanMux(
    ChanMux
    components/ChanMux/ChanMux_config.c
    system_config
)


DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
