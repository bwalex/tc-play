@api
Feature: API volume creation

  Scenario: Simple volume #1
    Given I create a volume tmpvol1 of size 10M using the API with the following parameters:
      | passphrase     | test             |
      | pbkdf_prf      | SHA512           |
      | cipher         | AES-256-XTS      |
    And I map volume tmpvol1 as tcplay_test with the API using the following settings:
      | passphrase     | test             |
    And I request information about volume tmpvol1 with the API using the following settings:
      | passphrase     | test             |
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

  Scenario: Cascade volume #1
    Given I create a volume tmpvol1 of size 10M using the API with the following parameters:
      | passphrase     | test                             |
      | pbkdf_prf      | whirlpool                        |
      | cipher         | AES-256-XTS,SERPENT-256-XTS      |
    And I map volume tmpvol1 as tcplay_test with the API using the following settings:
      | passphrase     | test             |
    And I request information about volume tmpvol1 with the API using the following settings:
      | passphrase     | test             |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test.0  | 0       | 19968   | serpent-xts-plain64   | 256       | 256           |
      | tcplay_test    | 0       | 19968   | aes-xts-plain64       | 256       | 0             |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | whirlpool                   |
      | Cipher             | AES-256-XTS,SERPENT-256-XTS |
      | Key Length         | 1024 bits                   |
      | Volume size        | 10223616 bytes              |
      | IV offset          | 131072 bytes                |
      | Block offset       | 131072 bytes                |

  Scenario: Hidden volume #1
    Given I create a volume tmpvol1 of size 10M using the API with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | keyfiles_hidden   | key.2                            |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I map volume tmpvol1 as tcplay_test with the API using the following settings:
      | passphrase     | test             |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 19968   | twofish-xts-plain64   | 256       | 256           |

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
    And I map volume tmpvol1 as tcplay_test with the API using the following settings:
      | keyfiles          | key.2             |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 4096    | serpent-xts-plain64   | 16128     | 16128         |

  Scenario: Hidden volume #3
    Given I create a volume tmpvol1 of size 10M using the API with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | passphrase_hidden | hiddenhidden                     |
      | keyfiles_hidden   | key.2, key.1                     |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I map volume tmpvol1 as tcplay_test with the API using the following settings:
      | passphrase        | hiddenhidden             |
      | keyfiles          | key.1, key.2             |
    And I request information about volume tmpvol1 with the API using the following settings:
      | passphrase        | hiddenhidden             |
      | keyfiles          | key.1, key.2             |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 4096    | serpent-xts-plain64   | 16128     | 16128         |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | RIPEMD160                   |
      | Cipher             | SERPENT-256-XTS             |
      | Key Length         | 512 bits                    |
      | Volume size        | 2097152 bytes               |
      | IV offset          | 8257536 bytes               |
      | Block offset       | 8257536 bytes               |
