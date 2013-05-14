@api
Feature: Passphrase 64-byte limitation using API

  Scenario: Long passphrase TrueCrypt-created volume mapping
    Given I map volume test_long.tc as tcplay_test with the API using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest   |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 1536    | aes-xts-plain64       | 256       | 256           |

  Scenario: Long passphrase TrueCrypt-created volume info
    Given I request information about volume test_long.tc with the API using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest   |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | RIPEMD160         |
      | Cipher             | AES-256-XTS       |
      | Key Length         | 512 bits          |
      | Volume size        | 786432 bytes      |
      | IV offset          | 131072 bytes      |
      | Block offset       | 131072 bytes      |

  Scenario: Long passphrase TrueCrypt-created volume mapping with trimming
    Given I map volume test_long.tc as tcplay_test with the API using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttestexceedslimitation   |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 1536    | aes-xts-plain64       | 256       | 256           |

  Scenario: Long passphrase TrueCrypt-created volume info with trimming
    Given I request information about volume test_long.tc with the API using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttestexceedslimitation   |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | RIPEMD160         |
      | Cipher             | AES-256-XTS       |
      | Key Length         | 512 bits          |
      | Volume size        | 786432 bytes      |
      | IV offset          | 131072 bytes      |
      | Block offset       | 131072 bytes      |

  Scenario: Long passphrase volume creation
    Given I create a volume tmpvol1 of size 10M using the API with the following parameters:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttestexceeds64chars   |
      | pbkdf_prf      | SHA512                                                                           |
      | cipher         | AES-256-XTS                                                                      |
    And I map volume tmpvol1 as tcplay_test with the API using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest   |
    And I request information about volume tmpvol1 with the API using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest   |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 19968   | aes-xts-plain64       | 256       | 256           |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | SHA512            |
      | Cipher             | AES-256-XTS       |
      | Key Length         | 512 bits          |
      | Volume size        | 10223616 bytes    |
      | IV offset          | 131072 bytes      |
      | Block offset       | 131072 bytes      |
