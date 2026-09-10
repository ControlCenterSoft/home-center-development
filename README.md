# Home Center

Home Center is an infrastructure-neutral platform for managing home and small-server infrastructure through a unified Web UI and API.

## Product source boundary

This repository contains public, infrastructure-neutral Home Center product source and documentation.

Home Center must be installable on a new or existing supported infrastructure without any dependency on a particular deployment. Product source must not hard-code real node names, domain names, directory identifiers, network addresses, credentials, certificates, or topology from an operator environment.

Runtime identity and topology are supplied by discovery, enrollment and deployment profiles. Directory integration is optional and configured by the administrator. Compute, storage, device, automation, certificate and remote-access providers are selected through capabilities and provider profiles rather than fixed hosts.

## Product UX architecture

Home Center has two complementary user-interface levels: the full technical interface and the accepted mobile-first interface **«Уютный»**. «Уютный» is part of Home Center, not a separate product or theme.

The authoritative architecture and release boundary for this interface are defined in [`docs/architecture/cozy-interface.md`](docs/architecture/cozy-interface.md).

The core rule is that the user expresses a household intent while Home Center translates it into a safe policy/desired-state plan and executes it through the normal authorization, Change/Job, reconciliation, verification and recovery boundaries. The published source line has advanced through 0.39.0; the separately published stable channel remains 0.15.0 until a newer stable release is completed. Household/Intent foundation starts with 0.26.0, and later user-facing capabilities are available only when explicitly published.

From 0.24 onward, every new user-facing capability should define both its Full/Core representation and its Household/Intent representation, or explicitly document why the latter is not applicable.

## Repository boundary

Allowed here:

- product source and Web UI;
- portable deployment and enrollment logic;
- schemas and API contracts;
- tests and public quality checks;
- infrastructure-neutral documentation and examples;
- release documentation and product examples.

Not allowed here:

- credentials, private keys or production certificates;
- real deployment IP addresses, host names, directory SIDs or private realms;
- operator-specific deployment overlays;
- production acceptance evidence containing private infrastructure details;
- internal server-only operational data.

Those restricted operational materials remain outside the public product source.

## Quality boundary

Changes to the public product source are required to pass repository quality, privacy and infrastructure-neutrality checks before they can be treated as release-ready.
