@cmdline
Feature: Command line VeraCrypt volume creation

  Scenario: Simple volume #1
    Given I create a volume tmpvol1 of size 10M with the following parameters:
      | passphrase     | testtest         |
      | pbkdf_prf      | SHA512-VC        |
      | cipher         | AES-256-XTS      |
    And I map volume tmpvol1 as tcplay_test using the following settings:
      | passphrase     | testtest         |
    And I request information about volume tmpvol1 using the following settings:
      | passphrase     | testtest         |
    Then I expect dmsetup to have the following tables:
      | name           | begin   | end     | algo                  | offset    | iv_offset     |
      | tcplay_test    | 0       | 19968   | aes-xts-plain64       | 256       | 256           |
    And I expect tcplay to report the following:
      | PBKDF2 PRF         | SHA512-VC         |
      | PBKDF2 iterations  | 500000            |
      | Cipher             | AES-256-XTS       |
      | Key Length         | 512 bits          |
      | Signature          | VERA              |
      | Sector size        | 512               |
      | Volume size        | 19968 sectors     |
      | IV offset          | 256 sectors       |
      | Block offset       | 256 sectors       |
