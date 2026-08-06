Feature: Social-firewall dashboard
  The dashboard is a real read-only HTTP page. These scenarios use a real
  Firefox/WebDriver session so the shipped CLI server and rendered HTML are
  exercised together.

  Scenario: An empty node explains its empty state
    Given an empty social-firewall database
    When I open the social-firewall dashboard
    Then the page title is "social-firewall dashboard"
    And the dashboard contains "read-only local dashboard"
    And the dashboard contains "no known groups"
    And the dashboard contains "no known device-approval opinions"

  Scenario: A group and its succession warning are visible
    Given a social-firewall database containing a group named "Neighborhood Watch"
    When I open the social-firewall dashboard
    Then the dashboard contains "Neighborhood Watch"
    And the dashboard contains "1 item(s) need attention"
    And the dashboard contains "Groups you own with a single owner"

  Scenario: Group names are escaped before reaching the browser
    Given a social-firewall database containing a group named "<script>alert(1)</script>"
    When I open the social-firewall dashboard
    Then the dashboard contains "<script>alert(1)</script>"
    And the dashboard source contains "&lt;script&gt;alert(1)&lt;/script&gt;"
    And the dashboard does not contain "<script>alert(1)</script>"
