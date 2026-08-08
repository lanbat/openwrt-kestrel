Feature: Two nodes share a federation group

  Background:
    Given Alice and Bob are separate functioning nodes
    And Alice and Bob belong to the same federation
    And Alice creates the "Neighborhood Watch" group
    And Bob has ingested the group snapshot

  Scenario: A member joins through owner approval
    When Bob requests to join "Neighborhood Watch"
    And Alice ingests Bob's join request
    Then Alice sees Bob as a pending member
    And Bob is not yet a member
    When Alice approves Bob as a voting member
    And Bob ingests the updated group snapshot
    Then Alice and Bob both list Bob as a voting member

  Scenario: A forged group update is rejected
    When Bob submits a forged update making himself the sole owner
    Then Alice rejects the group update
    And Alice's group membership is unchanged

  Scenario: Group votes converge between members
    Given Bob is an approved voting member of "Neighborhood Watch"
    When Alice votes to deny "203.0.113.9"
    And Bob votes to deny "203.0.113.9"
    And Bob ingests Alice's vote
    Then Bob's group explanation shows both votes
    And the group decision for "203.0.113.9" is "Deny"
