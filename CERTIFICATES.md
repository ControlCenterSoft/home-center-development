# Certificate requirements

Home Center Free keeps browser Web TLS and peer mTLS as independent identities. Do not reuse one private key for both roles.

## Peer mTLS

Provide `--peer-cert`, `--peer-key` and `--cluster-ca`. The peer certificate must contain DNS SAN `home-center-<node_name>` and the configured management IP SAN. The installer verifies the key pair and chain.

## Browser Web TLS

Provide `--web-cert`, `--web-key` and an independent `--web-ca`. The Web certificate must contain either the configured public hostname (when external access is enabled), the node name, or the management IP. The installer verifies the key pair and chain and installs the leaf into the immutable Web identity store used by Home Center.

The Web certificate and peer certificate must differ. The Web CA and cluster CA must also differ. Private keys are installed locally and are never part of the repository or public artifact.

## Lifecycle API

Authenticated administrators can read the secret-free inventory at `GET /api/v1/certificates` and request a deterministic, non-executable renewal plan at `POST /api/v1/certificates/renewal-plan`.

All lifecycle timestamps are required to include an explicit timezone and are normalized to UTC. The public lifecycle status is one of `valid`, `renewal_due`, or `expired`. Renewal plans contain only certificate identifiers, SHA-256 fingerprints, validation booleans, and ordered approval-gated actions. They never serialize or access private-key material, and `production_execution_enabled` is always `false`.
