@cmdline
Feature: Passphrase 64-byte limitation using command line

  Scenario: Long passphrase TrueCrypt-created volume mapping
    Given I map volume test_long.tc as tcplay_test using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest   |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 1536    | aes-xts-plain64       | 256       | 256           |

  Scenario: Long passphrase TrueCrypt-created volume info
    Given I request information about volume test_long.tc using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest   |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | RIPEMD160         |
      | PBKDF2 iterations  | 2000              |
      | Cipher             | AES-256-XTS       |
      | Key Length         | 512 bits          |
      | Sector size        | 512               |
      | Volume size        | 1536 sectors      |
      | IV offset          | 256 sectors       |
      | Block offset       | 256 sectors       |

  Scenario: Long passphrase TrueCrypt-created volume mapping with trimming
    Given I map volume test_long.tc as tcplay_test using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttestexceedslimitation   |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 1536    | aes-xts-plain64       | 256       | 256           |

  Scenario: Long passphrase TrueCrypt-created volume info with trimming
    Given I request information about volume test_long.tc using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttestexceedslimitation   |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | RIPEMD160         |
      | PBKDF2 iterations  | 2000              |
      | Cipher             | AES-256-XTS       |
      | Key Length         | 512 bits          |
      | Sector size        | 512               |
      | Volume size        | 1536 sectors      |
      | IV offset          | 256 sectors       |
      | Block offset       | 256 sectors       |

  Scenario: Long passphrase volume creation
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttestexceeds64chars   |
      | pbkdf_prf      | SHA512                                                                           |
      | cipher         | AES-256-XTS                                                                      |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest   |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase     | testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttest   |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 19968   | aes-xts-plain64       | 256       | 256           |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | SHA512            |
      | PBKDF2 iterations  | 1000              |
      | Cipher             | AES-256-XTS       |
      | Key Length         | 512 bits          |
      | Sector size        | 512               |
      | Volume size        | 19968 sectors     |
      | IV offset          | 256 sectors       |
      | Block offset       | 256 sectors       |
