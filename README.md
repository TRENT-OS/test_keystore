# test_keystore

Test application that tests seos_key_store functionalities. The application is a 
camkes system that is designed as part of the seos_test project. It contains the top 
level test runner which executes test cases:
    
    TestKeyStore_testCase_01
    TestKeyStore_testCase_02
    .
    .
    .
    TestKeyStore_testCase_17

For both the local and the remote version of the keystore.

Currently the test is configured to use FAT as the underlyinf filesystem, but SPIFFS can also be used by changing the flahg in the CMakeLists.txt

        # fs used by the keystore (FAT_FS / SPIF_FS)
        -DFAT_FS
        #-DSPIF_FS

### Build

The project is meant to be built as part of the seos_tests project
(https://bitbucket.hensoldt-cyber.systems/projects/HC/repos/seos_tests/browse)
