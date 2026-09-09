# Home Center

Home Center is an infrastructure-neutral platform for managing home and small-server infrastructure through a unified Web UI and API.

## Active development repository

This repository is the authoritative workspace for active Home Center product development.

Home Center must be installable on a new or existing supported infrastructure without any dependency on a particular deployment. Product source must not hard-code real node names, domain names, directory identifiers, network addresses, credentials, certificates, or topology from an operator environment.

Runtime identity and topology are supplied by discovery, enrollment and deployment profiles. Directory integration is optional and configured by the administrator. Compute, storage, device, automation, certificate and remote-access providers are selected through capabilities and provider profiles rather than fixed hosts.

## Product UX architecture

Home Center has two complementary user-interface levels: the full technical interface and the accepted mobile-first interface **«Уютный»**. «Уютный» is part of Home Center, not a separate product or theme.

The authoritative architecture and release boundary for this interface are defined in [`docs/architecture/cozy-interface.md`](docs/architecture/cozy-interface.md).

The core rule is that the user expresses a household intent while Home Center translates it into a safe policy/desired-state plan and executes it through the normal authorization, Change/Job, reconciliation, verification and recovery boundaries. The current 0.23 release scope is not expanded by this decision; the foundation starts with 0.24.

From 0.24 onward, every new user-facing capability should define both its Full/Core representation and its Household/Intent representation, or explicitly document why the latter is not applicable.

## Repository boundary

Allowed here:

- product source and Web UI;
- portable deployment and enrollment logic;
- schemas and API contracts;
- tests and GitHub Actions CI;
- infrastructure-neutral documentation and examples;
- release and feature branches for active development.

Not allowed here:

- credentials, private keys or production certificates;
- real deployment IP addresses, host names, directory SIDs or private realms;
- operator-specific deployment overlays;
- production acceptance evidence containing private infrastructure details;
- internal server-only operational data.

Those restricted operational materials remain outside the public product-development repository.

## Development model

`main` is the infrastructure-neutral integration baseline. Active versions are developed in parallel release and feature branches. Every push and pull request is checked by the infrastructure-neutrality gate on GitHub-hosted runners.
