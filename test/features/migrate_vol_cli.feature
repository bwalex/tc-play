@cmdline
Feature: Command line volume migration from TrueCrypt to VeraCrypt

  Scenario: Simple volume #1 (change PBKDF PRF)
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase     | test             |
      | pbkdf_prf      | SHA512           |
      | cipher         | AES-256-XTS      |
    And I modify volume tmpvol1 using the following settings:
      | passphrase     | test             |
      | new_passphrase | test             |
      | new_pbkdf_prf  | SHA512-VC        |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase     | test             |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase     | test             |
    Then I expect tcplay to succeed
    And I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 19968   | aes-xts-plain64       | 256       | 256           |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | SHA512-VC         |
      | PBKDF2 iterations  | 500000            |
      | Cipher             | AES-256-XTS       |
      | Signature          | VERA              |
      | Key Length         | 512 bits          |
      | Sector size        | 512               |
      | Volume size        | 19968 sectors     |
      | IV offset          | 256 sectors       |
      | Block offset       | 256 sectors       |
