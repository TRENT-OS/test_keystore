# test_keystore

Test application that tests seos_key_store functionalities. The application is a 
camkes system that is designed as part of the seos_test project. It contains the top 
level test runner which executes test cases:
    
    TestKeyStoreFAT_scenario_1
    TestKeyStoreFAT_scenario_2
    .
    .
    .
    TestKeyStoreFAT_scenario_10

and

    TestKeyStoreSPIFFS_scenario_1
    TestKeyStoreSPIFFS_scenario_2
    .
    .
    .
    TestKeyStoreSPIFFS_scenario_10

For both the local and the remote version of the keystore.

### Build

The project is meant to be built as part of the seos_tests project
(https://bitbucket.hensoldt-cyber.systems/projects/HC/repos/seos_tests/browse)
