@api
Feature: API query functions

  Scenario: Query ciphers
    Given I query the available ciphers with the API
    Then I expect to see the following ciphers:
      | name                                        | length  | klen    |
      | AES-256-XTS                                 | 1       | 64      |
      | TWOFISH-256-XTS                             | 1       | 64      |
      | SERPENT-256-XTS                             | 1       | 64      |
      | TWOFISH-256-XTS,AES-256-XTS                 | 2       | 128     |
      | AES-256-XTS,SERPENT-256-XTS                 | 2       | 128     |
      | SERPENT-256-XTS,TWOFISH-256-XTS             | 2       | 128     |
      | AES-256-XTS,TWOFISH-256-XTS,SERPENT-256-XTS | 3       | 192     |
      | SERPENT-256-XTS,TWOFISH-256-XTS,AES-256-XTS | 3       | 192     |

  Scenario: Query PRFs
    Given I query the available PRFs with the API
    Then I expect to see the following PRFs:
      | whirlpool |
      | SHA512    |
      | RIPEMD160 |
