@cmdline
Feature: Command line volume creation

  Scenario: Simple volume #1
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase     | test             |
      | pbkdf_prf      | SHA512           |
      | cipher         | AES-256-XTS      |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase     | test             |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase     | test             |
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

  Scenario: Cascade volume #1
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase     | test                             |
      | pbkdf_prf      | whirlpool                        |
      | cipher         | AES-256-XTS,SERPENT-256-XTS      |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase     | test             |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase     | test             |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test.0  | 0       | 19968   | serpent-xts-plain64   | 256       | 256           |
      | tcplay_test    | 0       | 19968   | aes-xts-plain64       | 256       | 0             |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | whirlpool                   |
      | PBKDF2 iterations  | 1000                        |
      | Cipher             | AES-256-XTS,SERPENT-256-XTS |
      | Key Length         | 1024 bits                   |
      | Sector size        | 512                         |
      | Volume size        | 19968 sectors               |
      | IV offset          | 256 sectors                 |
      | Block offset       | 256 sectors                 |

  Scenario: Hidden volume #1
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | keyfiles_hidden   | key.2                            |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase     | test             |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase     | test             |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 19968   | twofish-xts-plain64   | 256       | 256           |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | whirlpool                   |
      | PBKDF2 iterations  | 1000                        |
      | Cipher             | TWOFISH-256-XTS             |
      | Key Length         | 512 bits                    |
      | Sector size        | 512                         |
      | Volume size        | 19968 sectors               |
      | IV offset          | 256 sectors                 |
      | Block offset       | 256 sectors                 |

  Scenario: Hidden volume #2
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | keyfiles_hidden   | key.2                            |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | keyfiles          | key.2             |
      | prompt_skipped    | yes               |
    And I request information about volume tmpvol1 using the following settings:
      | keyfiles          | key.2             |
      | prompt_skipped    | yes               |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 4096    | serpent-xts-plain64   | 16128     | 16128         |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | RIPEMD160                   |
      | PBKDF2 iterations  | 2000                        |
      | Cipher             | SERPENT-256-XTS             |
      | Key Length         | 512 bits                    |
      | Sector size        | 512                         |
      | Volume size        | 4096 sectors                |
      | IV offset          | 16128 sectors               |
      | Block offset       | 16128 sectors               |

  Scenario: Hidden volume #3
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | passphrase_hidden | hiddenhidden                     |
      | keyfiles_hidden   | key.2, key.1                     |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase        | hiddenhidden             |
      | keyfiles          | key.1, key.2             |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase        | hiddenhidden             |
      | keyfiles          | key.1, key.2             |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 4096    | serpent-xts-plain64   | 16128     | 16128         |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | RIPEMD160                   |
      | PBKDF2 iterations  | 2000                        |
      | Cipher             | SERPENT-256-XTS             |
      | Key Length         | 512 bits                    |
      | Sector size        | 512                         |
      | Volume size        | 4096 sectors                |
      | IV offset          | 16128 sectors               |
      | Block offset       | 16128 sectors               |
