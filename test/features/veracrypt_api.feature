@api
Feature: VeraCrypt hidden volume protection with the API

  Scenario: Protect the hidden volume with its own PIM
    Given I map volume test_hidden_pim.vc as tcplay_test with the API using the following settings:
      | passphrase        | outer-volume-test-password  |
      | passphrase_hidden | hidden-volume-test-password |
      | keyfiles_hidden   | key.1, key.2                |
      | protect_hidden    | yes                         |
      | pim               | 7                           |
      | pim_hidden        | 13                          |
    Then I expect tcplay to succeed
    When I request information about mapped volume tcplay_test with the API
    Then I expect tcplay to report the following:
      | Volume size | 131072 bytes |

  Scenario: Refuse to map the outer volume with an incorrect hidden PIM
    Given I map volume test_hidden_pim.vc as tcplay_test with the API using the following settings:
      | passphrase        | outer-volume-test-password  |
      | passphrase_hidden | hidden-volume-test-password |
      | keyfiles_hidden   | key.1, key.2                |
      | protect_hidden    | yes                         |
      | pim               | 7                           |
      | pim_hidden        | 7                           |
    Then I expect tcplay to fail
    And I expect no mapping named tcplay_test
