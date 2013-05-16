@api
Feature: API mapping/info tests using volume test2.tc

  Scenario: Map outer volume
    Given I map volume test2.tc as tcplay_test with the API using the following settings:
      | passphrase         | test               |
    And I request information about mapped volume tcplay_test with the API
    Then I expect dmsetup to have the following tables:
      | name           | begin      | end         | algo                 | offset     | iv_offset    | key                                                                                                                              |
      | tcplay_test.1  | 0          | 9728        | aes-xts-plain64      | 256        | 256          | c0c4f02fd1f099388e80e387186b341ee90dec22083d1bcfdb402db247f5e829d84da25ed03101645953c4d265fc4e9be56a8c313527a6be49c82b67304e5844 |
      | tcplay_test.0  | 0          | 9728        | twofish-xts-plain64  | 256        | 0            | 48aefeb402d01bffcd1aaf6db82f92c5951faefd6abd4ed26f10b0c0cd5bfc189c3a34ece236a2c614d39b8e97d2bc42495382dca757b03c9bfb26bb9d4f3dbb |
      | tcplay_test    | 0          | 9728        | serpent-xts-plain64  | 256        | 0            | ab2ac0b2007a0ead7a26d5560fb4d385ab4b59d38a7794f211ae7a6f91e97cd388d5bda1bf57be14be1b39bf514873470006c687c03041b5fbeb47aa5cc3a065 |
    And I expect tcplay to report the following:
      | Cipher             | SERPENT-256-XTS,TWOFISH-256-XTS,AES-256-XTS |
      | Key Length         | 1536 bits                                   |
      | Volume size        | 4980736 bytes                               |
      | IV offset          | 131072 bytes                                |
      | Block offset       | 131072 bytes                                |



  Scenario: Map hidden volume
    Given I map volume test2.tc as tcplay_test with the API using the following settings:
      | passphrase         | hidden             |
      | keyfiles           | key.1, key.2       |
    And I request information about mapped volume tcplay_test with the API
    Then I expect dmsetup to have the following tables:
      | name           | begin      | end         | algo                 | offset     | iv_offset    | key                                                                                                                              |
      | tcplay_test.0  | 0          | 2040        | twofish-xts-plain64  | 7936       | 7936         | 9063947314787d4645bfb609461e8636f7f103dc82631897ed35e2aacf5d651266fb409395d337ecf91578d446cedb5f3979058c79399416850c512060bfaf20 |
      | tcplay_test    | 0          | 2040        | serpent-xts-plain64  | 7936       | 0            | fbdfcc05d46e450accb6c7b17c58de8807a39ef1b61bb5347f21b9fc65e9bd3c13e7c0818df5d76a56055abafb8fa2dd3878140996172e418970857a20509509 |
    And I expect tcplay to report the following:
      | Cipher             | SERPENT-256-XTS,TWOFISH-256-XTS             |
      | Key Length         | 1024 bits                                   |
      | Volume size        | 1044480 bytes                               |
      | IV offset          | 4063232 bytes                               |
      | Block offset       | 4063232 bytes                               |



  Scenario: Map outer volume protecting hidden volume
    Given I map volume test2.tc as tcplay_test with the API using the following settings:
      | passphrase         | test               |
      | passphrase_hidden  | hidden             |
      | keyfiles_hidden    | key.1, key.2       |
      | protect_hidden     | yes                |
    And I request information about mapped volume tcplay_test with the API
    Then I expect dmsetup to have the following tables:
      | name           | begin      | end         | algo                 | offset     | iv_offset    | key                                                                                                                              |
      | tcplay_test.1  | 0          | 7688        | aes-xts-plain64      | 256        | 256          | c0c4f02fd1f099388e80e387186b341ee90dec22083d1bcfdb402db247f5e829d84da25ed03101645953c4d265fc4e9be56a8c313527a6be49c82b67304e5844 |
      | tcplay_test.0  | 0          | 7688        | twofish-xts-plain64  | 256        | 0            | 48aefeb402d01bffcd1aaf6db82f92c5951faefd6abd4ed26f10b0c0cd5bfc189c3a34ece236a2c614d39b8e97d2bc42495382dca757b03c9bfb26bb9d4f3dbb |
      | tcplay_test    | 0          | 7688        | serpent-xts-plain64  | 256        | 0            | ab2ac0b2007a0ead7a26d5560fb4d385ab4b59d38a7794f211ae7a6f91e97cd388d5bda1bf57be14be1b39bf514873470006c687c03041b5fbeb47aa5cc3a065 |
    And I expect tcplay to report the following:
      | Cipher             | SERPENT-256-XTS,TWOFISH-256-XTS,AES-256-XTS |
      | Key Length         | 1536 bits                                   |
      | Volume size        | 3936256 bytes                               |
      | IV offset          | 131072 bytes                                |
      | Block offset       | 131072 bytes                                |



  Scenario: Info on outer volume
    Given I request information about volume test2.tc with the API using the following settings:
      | passphrase         | test               |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | RIPEMD160                                   |
      | Cipher             | SERPENT-256-XTS,TWOFISH-256-XTS,AES-256-XTS |
      | Key Length         | 1536 bits                                   |
      | Volume size        | 4980736 bytes                               |
      | IV offset          | 131072 bytes                                |
      | Block offset       | 131072 bytes                                |



  Scenario: Map hidden volume
    Given I request information about volume test2.tc with the API using the following settings:
      | passphrase         | hidden             |
      | keyfiles           | key.1, key.2       |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | SHA512                                      |
      | Cipher             | SERPENT-256-XTS,TWOFISH-256-XTS             |
      | Key Length         | 1024 bits                                   |
      | Volume size        | 1044480 bytes                               |
      | IV offset          | 4063232 bytes                               |
      | Block offset       | 4063232 bytes                               |



  Scenario: Map outer volume protecting hidden volume
    Given I request information about volume test2.tc with the API using the following settings:
      | passphrase         | test               |
      | passphrase_hidden  | hidden             |
      | keyfiles_hidden    | key.1, key.2       |
      | protect_hidden     | yes                |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | RIPEMD160                                   |
      | Cipher             | SERPENT-256-XTS,TWOFISH-256-XTS,AES-256-XTS |
      | Key Length         | 1536 bits                                   |
      | Volume size        | 3936256 bytes                               |
      | IV offset          | 131072 bytes                                |
      | Block offset       | 131072 bytes                                |
