Feature: Domain rule approval with WAN/VPN split-routing

  Scenario: Approving a domain with no route defaults to WAN
    Given the "guest" network is installed
    And a device "aa:bb:cc:dd:ee:01"
    When the device approves domain "example.com" on "guest" with no route
    Then the request succeeds
    And the "guest" rules file has a rule for domain "example.com" routed via "WAN"

  Scenario: Approving a domain routed through a configured VPN tier
    Given the "guest" network is installed
    And a VPN tier "bg" is configured with fwmark "0x1"
    And a device "aa:bb:cc:dd:ee:02"
    When the device approves domain "torrent-tracker.example" on "guest" routed via "bg"
    Then the request succeeds
    And the "guest" rules file has a rule for domain "torrent-tracker.example" routed via "bg"

  Scenario: Approving a domain with an unrecognized route is rejected
    Given the "guest" network is installed
    And a VPN tier "bg" is configured with fwmark "0x1"
    And a device "aa:bb:cc:dd:ee:03"
    When the device approves domain "example.com" on "guest" routed via "nonexistent"
    Then the request is rejected with error "Unknown VPN route"

  Scenario: Re-approving the same domain with a different route replaces the old rule
    Given the "guest" network is installed
    And a VPN tier "bg" is configured with fwmark "0x1"
    And a VPN tier "uk" is configured with fwmark "0x2"
    And a device "aa:bb:cc:dd:ee:04"
    When the device approves domain "example.com" on "guest" routed via "bg"
    And the device approves domain "example.com" on "guest" routed via "uk"
    Then the request succeeds
    And the "guest" rules file has a rule for domain "example.com" routed via "uk"
    And the "guest" rules file has exactly one rule for domain "example.com"
