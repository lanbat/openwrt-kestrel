Feature: Browser-driven approve workflow
  join_approval.feature already proves the backend handler's file-state
  transitions in isolation. What it can't see is the dashboard's own
  client-side JS (_jsonpost.html's fetch-then-reload behavior on the
  Approve/Deny buttons) — that only exists once real HTML is rendered and
  a real browser executes it. This drives an actual (headless) Firefox
  against a real, freshly-started kestreld instance to close that gap.

  Scenario: Approving a pending device in the browser updates its row
    Given the "guest" network is installed with join approval enabled
    And a device "aa:bb:cc:dd:ee:99" at "192.168.3.200" is pending join on "guest"
    When I open the dashboard in a browser
    And I approve that device with label "Browser Test Phone"
    Then the dashboard shows that device as "Approved"

  Scenario: Approving a domain routed via a VPN tier updates the rules table
    Given the "guest" network is installed with join approval enabled
    And a VPN tier "bg" is configured with fwmark "0x1"
    And a device "aa:bb:cc:dd:ee:98" at "192.168.3.201" is pending join on "guest"
    When I open the device page for "aa:bb:cc:dd:ee:98" on "guest" in a browser
    And I approve domain "example.com" routed via "bg"
    Then the rules table shows domain "example.com" routed via "BG"
