@api
Feature: Save header to file
  Background:
    Given I create a volume tmpvol1 of size 10M using the API with the following parameters:
      | passphrase        | test                             |

  Scenario: Save header with changed passphrase to file
    Given I modify volume tmpvol1 with the API by saving a header copy to tmpvol1_hdr using the following settings:
      | passphrase        | test        |
    And I modify volume tmpvol1 with the API using the following settings:
      | passphrase     | test             |
      | new_passphrase | new              |
    And I request information about volume tmpvol1 with the API using the following settings:
      | passphrase     | test             |
    Then I expect tcplay to fail

  Scenario: Use saved header to access volume with changed passphrase
    Given I modify volume tmpvol1 with the API by saving a header copy to tmpvol1_hdr using the following settings:
      | passphrase        | test        |
    And I modify volume tmpvol1 with the API using the following settings:
      | passphrase     | test             |
      | new_passphrase | new              |
    And I request information about volume tmpvol1 with the API using the following settings:
      | passphrase     | test             |
      | header_file    | tmpvol1_hdr      |
    Then I expect tcplay to report the following:
      | Key Length         | 512 bits                    |
