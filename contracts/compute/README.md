# Compute provider boundary

Home Center 0.16 plans VM and container placement from immutable provider and
capacity observations. The boundary is infrastructure-neutral: a provider is
identified by a profile and versioned capabilities, never by a built-in host,
address, credential, storage name, or cluster name.

## Provider adapter rules

An adapter publishes:

- a stable `provider_id` local to the Home Center installation;
- a versioned `profile_id`;
- its currently enabled versioned capabilities;
- a monotonically increasing capacity `sequence`;
- total, already allocated, and administrator-reserved capacity.

`proxmox.virtualization.v1` is a bundled profile with VM, generic-container,
LXC, HA, and capacity capabilities. It is not a connection configuration and
grants no execution authority. Other adapters use the same types and planner.

## Planning semantics

The planner subtracts allocated and reserved capacity, then evaluates every
provider in ascending `provider_id` order. A provider is blocked when it is
unhealthy, lacks the requested runtime or HA/capacity capability, reports
inconsistent accounting, or has insufficient CPU, memory, or storage.

Eligible providers are ranked by the greatest projected CPU, memory, or
storage utilization in basis points. Lowest utilization wins; equal results
use ascending `provider_id`. This integer-only policy is identified as
`least-utilized-then-provider-id.v1`, making the output independent of input
ordering and floating-point behavior.

The endpoint only returns a plan. `production_mutation_enabled` is always
`false`; resource creation requires a separate lifecycle and authorization
boundary.
