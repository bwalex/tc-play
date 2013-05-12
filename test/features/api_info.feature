@api
Feature: Info command via API

  Scenario: Info on outer volume
    Given I request information about volume test1.tc with the API using the following settings:
      | passphrase         | test               |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | whirlpool          |
      | Cipher             | AES-256-XTS        |
      | Key Length         | 512 bits           |
      | Volume size        | 20709376 bytes     |
      | IV offset          | 131072 bytes       |
      | Block offset       | 131072 bytes       |

  Scenario: Info on hidden volume
    Given I request information about volume test1.tc with the API using the following settings:
      | passphrase         | hidden             |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | whirlpool          |
      | Cipher             | AES-256-XTS        |
      | Key Length         | 512 bits           |
      | Volume size        | 5242880 bytes      |
      | IV offset          | 15597568 bytes     |
      | Block offset       | 15597568 bytes     |


  Scenario: Info on outer volume protecting hidden volume
    Given I request information about volume test1.tc with the API using the following settings:
      | passphrase         | test               |
      | passphrase_hidden  | hidden             |
      | protect_hidden     | yes                |
    Then I expect tcplay to report the following:
      | PBKDF2 PRF         | whirlpool          |
      | Cipher             | AES-256-XTS        |
      | Key Length         | 512 bits           |
      | Volume size        | 15466496 bytes     |
      | IV offset          | 131072 bytes       |
      | Block offset       | 131072 bytes       |

