@cmdline
Feature: Command line info/map using VeraCrypt volumes

  Scenario: Map volume in test_sha512.vc
    Given I map volume test_sha512.vc as tcplay_test using the following settings:
      | passphrase         | testtesttest       |
    And I request information about mapped volume tcplay_test
    Then I expect dmsetup to have the following tables:
      | name           | begin      | end         | algo                 | offset     | iv_offset    | key                                                                                                                              |
      | tcplay_test    | 0          | 512         | aes-xts-plain64      | 256        | 256          | 267ee31a19240a058a60b229fe44d51b715ed41b5bb97b4970ed64fff0e5bd7b1efc9e3de24ba65232d97d5705c04612506254912b7d23310e5000cc524aacb0 |
    And I expect tcplay to report the following:
      | Cipher             | AES-256-XTS                                 |
      | Key Length         | 512 bits                                    |
      | Volume size        | 512 sectors                                 |
      | IV offset          | 256 sectors                                 |
      | Block offset       | 256 sectors                                 |

  Scenario: Info about volume test_sha512.vc
    Given I request information about volume test_sha512.vc using the following settings:
      | passphrase         | testtesttest       |
    And I expect tcplay to report the following:
      | Cipher             | AES-256-XTS                                 |
      | PBKDF2 PRF         | SHA512-VC                                   |
      | Key Length         | 512 bits                                    |
      | Signature          | VERA                                        |
      | Volume size        | 512 sectors                                 |
      | IV offset          | 256 sectors                                 |
      | Block offset       | 256 sectors                                 |

  Scenario: Info about volume test_whirlpool.vc
    Given I request information about volume test_whirlpool.vc using the following settings:
      | passphrase         | testtest       |
    And I expect tcplay to report the following:
      | Cipher             | TWOFISH-256-XTS                             |
      | PBKDF2 PRF         | whirlpool-VC                                |
      | Key Length         | 512 bits                                    |
      | Signature          | VERA                                        |
      | Volume size        | 512 sectors                                 |
      | IV offset          | 256 sectors                                 |
      | Block offset       | 256 sectors                                 |


  Scenario: Info about volume test_sha256.vc
    Given I request information about volume test_sha256.vc using the following settings:
      | passphrase         | testtest       |
    And I expect tcplay to report the following:
      | Cipher             | TWOFISH-256-XTS,AES-256-XTS                 |
      | PBKDF2 PRF         | SHA256-VC                                   |
      | Key Length         | 1024 bits                                   |
      | Signature          | VERA                                        |
      | Volume size        | 512 sectors                                 |
      | IV offset          | 256 sectors                                 |
      | Block offset       | 256 sectors                                 |
