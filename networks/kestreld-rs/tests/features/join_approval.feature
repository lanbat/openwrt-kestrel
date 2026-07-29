Feature: Join approval process
  New devices that associate to a JOIN_APPROVAL=yes network (guest, untrusted)
  are held back from internet access until an admin approves or denies them
  from the dashboard / push notification. This covers the /cgi-bin/approve-join
  handler's file-based state transitions for both network profiles.

  Scenario Outline: A pending device is approved with a label
    Given the "<network>" network is installed with join approval enabled
    And a device "aa:bb:cc:dd:ee:01" at "<ip>" is pending join on "<network>"
    When the device is approved on "<network>" with label "<label>"
    Then the request succeeds
    And "aa:bb:cc:dd:ee:01" is approved on "<network>"
    And "aa:bb:cc:dd:ee:01" is no longer pending on "<network>"
    And "aa:bb:cc:dd:ee:01" is labeled "<label>" on "<network>"
    And a join history entry "approved" exists for "aa:bb:cc:dd:ee:01" on "<network>"

    Examples:
      | network   | ip            | label          |
      | guest     | 192.168.3.100 | Alice's Phone  |
      | untrusted | 192.168.4.100 | Kitchen Sensor |

  Scenario Outline: Approval is refused without a label when none was set before
    Given the "<network>" network is installed with join approval enabled
    And a device "aa:bb:cc:dd:ee:02" at "<ip>" is pending join on "<network>"
    When the device is approved on "<network>" with label ""
    Then the request is rejected with error "Label is required to approve a device"
    And "aa:bb:cc:dd:ee:02" is still pending on "<network>"

    Examples:
      | network   | ip            |
      | guest     | 192.168.3.101 |
      | untrusted | 192.168.4.101 |

  Scenario Outline: Approving with no label reuses a previously saved label
    Given the "<network>" network is installed with join approval enabled
    And a device "aa:bb:cc:dd:ee:03" at "<ip>" is pending join on "<network>"
    And "aa:bb:cc:dd:ee:03" was already labeled "Old Roomba" on "<network>"
    When the device is approved on "<network>" with label ""
    Then the request succeeds
    And "aa:bb:cc:dd:ee:03" is labeled "Old Roomba" on "<network>"

    Examples:
      | network   | ip            |
      | guest     | 192.168.3.102 |
      | untrusted | 192.168.4.102 |

  Scenario Outline: A pending device is denied
    Given the "<network>" network is installed with join approval enabled
    And a device "aa:bb:cc:dd:ee:04" at "<ip>" is pending join on "<network>"
    When the device is denied on "<network>"
    Then the request succeeds
    And "aa:bb:cc:dd:ee:04" is denied on "<network>"
    And "aa:bb:cc:dd:ee:04" is still pending on "<network>"
    And a join history entry "denied" exists for "aa:bb:cc:dd:ee:04" on "<network>"

    Examples:
      | network   | ip            |
      | guest     | 192.168.3.103 |
      | untrusted | 192.168.4.103 |

  Scenario: Approving on untrusted also tracks the device's IP for outbound inspection
    Given the "untrusted" network is installed with join approval enabled
    And a device "aa:bb:cc:dd:ee:05" at "192.168.4.104" is pending join on "untrusted"
    When the device is approved on "untrusted" with label "IoT Cam"
    Then the request succeeds
    And "aa:bb:cc:dd:ee:05" has its IP tracked for device control on "untrusted"

  Scenario: Approving on guest does not track a per-device IP (device control is off)
    Given the "guest" network is installed with join approval enabled
    And a device "aa:bb:cc:dd:ee:06" at "192.168.3.104" is pending join on "guest"
    When the device is approved on "guest" with label "Bob's Laptop"
    Then the request succeeds
    And "aa:bb:cc:dd:ee:06" has no IP tracked for device control on "guest"

  Scenario Outline: Requests from outside the LAN are rejected regardless of network
    Given the "<network>" network is installed with join approval enabled
    And a device "aa:bb:cc:dd:ee:07" at "<ip>" is pending join on "<network>"
    When the device is approved on "<network>" with label "Attacker" from origin "http://evil.example.com"
    Then the request is rejected with error "Forbidden"
    And "aa:bb:cc:dd:ee:07" is still pending on "<network>"

    Examples:
      | network   | ip            |
      | guest     | 192.168.3.105 |
      | untrusted | 192.168.4.105 |

  Scenario: Bulk-approving only approves pending devices that already have a label
    Given the "guest" network is installed with join approval enabled
    And a device "aa:bb:cc:dd:ee:08" at "192.168.3.106" is pending join on "guest"
    And "aa:bb:cc:dd:ee:08" was already labeled "Known Laptop" on "guest"
    And a device "aa:bb:cc:dd:ee:09" at "192.168.3.107" is pending join on "guest"
    When the guest network's labeled pending devices are bulk-approved
    Then the request succeeds
    And "aa:bb:cc:dd:ee:08" is approved on "guest"
    And "aa:bb:cc:dd:ee:09" is still pending on "guest"

  Scenario: Approving a randomized-MAC device with a gathered fingerprint learns it for next time
    Given the "guest" network is installed with join approval enabled
    And a device "02:aa:bb:cc:dd:ee" at "192.168.3.110" is pending join on "guest"
    When the device is approved on "guest" with label "Kirils Phone" and mDNS name "Kirils-Phone" model "iPhone16,2"
    Then the request succeeds
    And the "guest" fingerprint registry has an entry for "Kirils Phone" with mDNS name "Kirils-Phone"

  Scenario: Approving a fixed (non-randomized) MAC does not create a fingerprint entry
    Given the "guest" network is installed with join approval enabled
    And a device "00:11:22:33:44:55" at "192.168.3.111" is pending join on "guest"
    When the device is approved on "guest" with label "Office Printer" and mDNS name "Office-Printer" model "LaserJet"
    Then the request succeeds
    And the "guest" fingerprint registry has no entry for "Office Printer"

  Scenario: Renaming a device's label updates its fingerprint identity in place
    Given the "guest" network is installed with join approval enabled
    And a device "02:aa:bb:cc:dd:ff" at "192.168.3.112" is pending join on "guest"
    And the device is approved on "guest" with label "Kirils Phone" and mDNS name "Kirils-Phone2" model "iPhone16,2"
    When the device's label on "guest" is changed to "Kiril's iPhone 16"
    Then the "guest" fingerprint registry has an entry for "Kiril's iPhone 16" with mDNS name "Kirils-Phone2"
    And the "guest" fingerprint registry has no entry for "Kirils Phone"
