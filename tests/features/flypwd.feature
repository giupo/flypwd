Feature: Manager passwords in a secure manner
  In order to handle passwords efficiently and safely
  As a software developer, or as a service
  I'll manage them via flypwd

  Scenario: I have want to store a password
    Given I have the password pippo
    When I use flypwd
    Then I retrieve the password pippo


  Scenario: I have want to store a password for a service
    Given I have the password pippo
    And I have the service pluto
    When I use flypwd
    Then I have a file named pluto 
    and I retrieve the password pippo
