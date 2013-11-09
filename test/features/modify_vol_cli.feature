@cmdline
Feature: Command line volume modification

  Scenario: Simple volume #1 (change passphrase, pos)
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase     | test             |
      | pbkdf_prf      | SHA512           |
      | cipher         | AES-256-XTS      |
    And I modify volume tmpvol1 using the following settings:
      | passphrase     | test             |
      | new_passphrase | new              |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase     | new              |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase     | new              |
    Then I expect tcplay to succeed
    And I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 19968   | aes-xts-plain64       | 256       | 256           |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | SHA512            |
      | PBKDF2 iterations  | 1000              |
      | Cipher             | AES-256-XTS       |
      | Key Length         | 512 bits          |
      | Sector size        | 512               |
      | Volume size        | 19968 sectors     |
      | IV offset          | 256               |
      | Block offset       | 256               |

  Scenario: Simple volume #1 (change PBKDF PRF)
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase     | test             |
      | pbkdf_prf      | SHA512           |
      | cipher         | AES-256-XTS      |
    And I modify volume tmpvol1 using the following settings:
      | passphrase     | test             |
      | new_passphrase | test             |
      | new_pbkdf_prf  | whirlpool        |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase     | test             |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase     | test             |
    Then I expect tcplay to succeed
    And I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 19968   | aes-xts-plain64       | 256       | 256           |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | whirlpool         |
      | PBKDF2 iterations  | 1000              |
      | Cipher             | AES-256-XTS       |
      | Key Length         | 512 bits          |
      | Sector size        | 512               |
      | Volume size        | 19968 sectors     |
      | IV offset          | 256               |
      | Block offset       | 256               |

  Scenario: Cascade volume #1 (change passphrase)
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase     | test                             |
      | pbkdf_prf      | whirlpool                        |
      | cipher         | AES-256-XTS,SERPENT-256-XTS      |
    And I modify volume tmpvol1 using the following settings:
      | passphrase     | test             |
      | new_passphrase | new              |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase     | new              |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase     | new              |
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
      | IV offset          | 256                         |
      | Block offset       | 256                         |

  Scenario: Hidden volume #1 (change passphrase)
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | keyfiles_hidden   | key.2                            |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I modify volume tmpvol1 using the following settings:
      | keyfiles       | key.2             |
      | new_passphrase | new_hidden        |
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
      | IV offset          | 256                         |
      | Block offset       | 256                         |

  Scenario: Hidden volume #2 (change passphrase, keyfiles)
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | keyfiles_hidden   | key.2                            |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I modify volume tmpvol1 using the following settings:
      | keyfiles       | key.2             |
      | prompt_skipped | yes               |
      | new_passphrase | new_hidden        |
      | new_keyfiles   | key.1, key.2      |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase        | new_hidden     |
      | keyfiles          | key.1, key.2   |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase        | new_hidden     |
      | keyfiles          | key.1, key.2   |
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
      | IV offset          | 16128                       |
      | Block offset       | 16128                       |

  Scenario: Hidden volume #3 (change keyfiles, PBKDF PRF)
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | keyfiles_hidden   | key.2                            |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I modify volume tmpvol1 using the following settings:
      | keyfiles       | key.2             |
      | new_keyfiles   | key.1, key.2      |
      | new_pbkdf_prf  | SHA512            |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | keyfiles          | key.1, key.2   |
      | prompt_skipped    | yes            |
    And I request information about volume tmpvol1 using the following settings:
      | keyfiles          | key.1, key.2   |
      | prompt_skipped    | yes            |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 4096    | serpent-xts-plain64   | 16128     | 16128         |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | SHA512                      |
      | PBKDF2 iterations  | 1000                        |
      | Cipher             | SERPENT-256-XTS             |
      | Key Length         | 512 bits                    |
      | Sector size        | 512                         |
      | Volume size        | 4096 sectors                |
      | IV offset          | 16128                       |
      | Block offset       | 16128                       |

  Scenario: Hidden volume #4 (restore from backup, outer)
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | keyfiles_hidden   | key.2                            |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I corrupt sector 0 of volume tmpvol1
    And I modify volume tmpvol1 by restoring from the backup header using the following settings:
      | passphrase     | test             |
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
      | IV offset          | 256                         |
      | Block offset       | 256                         |

  Scenario: Hidden volume #5 (restore from backup, hidden)
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase        | test                             |
      | pbkdf_prf         | whirlpool                        |
      | cipher            | TWOFISH-256-XTS                  |
      | create_hidden     | yes                              |
      | hidden_mb         | 2                                |
      | keyfiles_hidden   | key.2                            |
      | pbkdf_prf_hidden  | RIPEMD160                        |
      | cipher_hidden     | SERPENT-256-XTS                  |
    And I corrupt sector 128 of volume tmpvol1
    And I modify volume tmpvol1 by restoring from the backup header using the following settings:
      | keyfiles          | key.2          |
      | prompt_skipped    | yes            |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | keyfiles          | key.2          |
      | prompt_skipped    | yes            |
    And I request information about volume tmpvol1 using the following settings:
      | keyfiles          | key.2          |
      | prompt_skipped    | yes            |
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
      | IV offset          | 16128                       |
      | Block offset       | 16128                       |
