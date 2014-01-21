@api
Feature: Use header from file
  Background:
    Given I create a volume tmpvol1 of size 10M using the API with the following parameters:
      | passphrase        | test     |
    And I modify volume tmpvol1 with the API by saving a header copy to tmpvol1_hdr using the following settings:
      | passphrase        | test     |
    And I corrupt sectors 0 to 20479 of volume tmpvol1

  Scenario: Corrupted volume cannot be accessed
    Given I request information about volume tmpvol1 with the API using the following settings:
      | passphrase        | test     |
    Then I expect tcplay to fail

  Scenario: Access a volume with header file when all volume headers are corrupted
    Given I request information about volume tmpvol1 with the API using the following settings:
      | passphrase        | test        |
      | header_file       | tmpvol1_hdr |
    Then I expect tcplay to report the following:
      | Key Length         | 512 bits                    |

  Scenario: Restore volume headers from copy in file
    Given I modify volume tmpvol1 with the API by restoring from header copy tmpvol1_hdr using the following settings:
      | passphrase        | test        |
    And I request information about volume tmpvol1 with the API using the following settings:
      | passphrase        | test        |
    Then I expect tcplay to report the following:
      | Key Length         | 512 bits                    |
