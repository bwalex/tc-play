@cmdline
Feature: Command line mapping/info tests using volume test1.tc

  Scenario: Map outer volume
    Given I map volume test1.tc as tcplay_test using the following settings:
      | passphrase         | test               |
    Then I expect dmsetup to have the following tables:
      | name         | begin      | end         | algo                 | offset     | iv_offset    | key                                                                                                                              |
      | tcplay_test  | 0          | 40448       | aes-xts-plain64      | 256        | 256          | b736aebe0ba9e67f58f110769955a19d1351b07f99cbda9f59249e0aaed72f9e672365dee6d2bf00a34bdd1b8aafa31b274103b9e925ac568e60562ce0c6ff0e |



  Scenario: Map hidden volume
    Given I map volume test1.tc as tcplay_test using the following settings:
      | passphrase         | hidden             |
    Then I expect dmsetup to have the following tables:
      | name         | begin      | end         | algo                 | offset     | iv_offset    | key                                                                                                                              |
      | tcplay_test  | 0          | 10240       | aes-xts-plain64      | 30464      | 30464        | 7dd9086e92b756f55465723a9b4594bf61040a6bea8b2291a45821ff80d0676dd86caf6595d57beb7902e952706fbb7bad8b69048c47cced1aba08ebac847dd9 |



  Scenario: Map outer volume protecting hidden volume
    Given I map volume test1.tc as tcplay_test using the following settings:
      | passphrase         | test               |
      | passphrase_hidden  | hidden             |
      | protect_hidden     | yes                |
    Then I expect dmsetup to have the following tables:
      | name         | begin      | end         | algo                 | offset     | iv_offset    | key                                                                                                                              |
      | tcplay_test  | 0          | 30208       | aes-xts-plain64      | 256        | 256          | b736aebe0ba9e67f58f110769955a19d1351b07f99cbda9f59249e0aaed72f9e672365dee6d2bf00a34bdd1b8aafa31b274103b9e925ac568e60562ce0c6ff0e |



