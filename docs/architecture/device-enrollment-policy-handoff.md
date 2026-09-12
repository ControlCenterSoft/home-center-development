# Device enrollment → policy handoff (Home Center 0.58)

Home Center 0.58 intentionally separates successful device enrollment from policy application. A verified provider post-condition may authorize only the local transition `ManagedDevice.managed=false -> true`. It does **not** authorize MDM, family, network, firewall, application or other policy changes.

`home-center.device-management-enrollment-policy-handoff.v1` is the boundary between the 0.58 enrollment lifecycle and the later policy-planning lifecycle. It is derived only from the terminal, audited `managed-state-committed` receipt and binds the exact verification, enrollment execution, Household snapshot/resource version, device/member and commit audit evidence.

The handoff is non-mutating. It always has:

- `policy_context_ready=true`;
- `separate_policy_plan_required=true`;
- `separate_confirmation_required=true`;
- `policy_application_authorized=false`;
- `policy_execution_authorized=false`;
- `provider_mutation_authorized=false`;
- `infrastructure_mutation_authorized=false`;
- `external_publication_authorized=false`.

Therefore a consumer in 0.59 or later must create a new policy plan from current Desired/Actual State, revalidate current Household/resource identity, show the change to an authorized user, obtain a separate confirmation and only then enter its own durable Job/Audit execution path. The enrollment handoff cannot be used as a confirmation token and cannot be promoted into execution authority.

This keeps the «Уютный» UX safe: “подключить устройство” and “применить правила к устройству” may be presented as one guided scenario, but internally they remain two explicit safety boundaries with independent evidence and recovery semantics.
