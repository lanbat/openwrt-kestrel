Feature: Social-firewall party-line chat
  The chat page is served through the same CGI entrypoint installed on the
  router. The test uses a local CGI shim only to provide HTTP to WebDriver;
  each request still runs the real sf binary and CLI parser.

  Scenario: The chat page renders a self group and message form
    Given a social-firewall chat database with a self group
    When I open the social-firewall chat
    Then the chat title is "social-firewall chat"
    And the chat contains "party-line chat"
    And the chat contains "send"
    And the chat uses the bundled Fixedsys font

  Scenario: Sending a party-line message through the browser invokes sf
    Given a social-firewall chat database with a self group
    When I open the social-firewall chat
    And I send the party-line message "hello from WebDriver"
    Then the chat contains "hello from WebDriver"

  Scenario: Command completion shows inline fish-style documentation
    Given a social-firewall chat database with a self group
    When I open the social-firewall chat
    And I type the command prefix "/top"
    Then the command suggestions include "/topic"
    And the command documentation includes "Show or change the current group topic."
