# Certificate requirements

Home Center Free keeps browser Web TLS and peer mTLS as independent identities. Do not reuse one private key for both roles.

## Peer mTLS

Provide `--peer-cert`, `--peer-key` and `--cluster-ca`. The peer certificate must contain DNS SAN `home-center-<node_name>` and the configured management IP SAN. The installer verifies the key pair and chain.

## Browser Web TLS

Provide `--web-cert`, `--web-key` and an independent `--web-ca`. The Web certificate must contain either the configured public hostname (when external access is enabled), the node name, or the management IP. The installer verifies the key pair and chain and installs the leaf into the immutable Web identity store used by Home Center.

The Web certificate and peer certificate must differ. The Web CA and cluster CA must also differ. Private keys are installed locally and are never part of the repository or public artifact.
