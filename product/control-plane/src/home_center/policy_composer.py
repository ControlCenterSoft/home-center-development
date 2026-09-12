"""Policy Composer v1 foundation for Home Center 0.59.

This module is intentionally non-mutating. It composes bounded, monotonic household
policy restrictions into an EffectivePolicy preview without authorizing production
changes. The execution/apply path remains owned by DesiredState/Job workflows.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Final, Iterable

from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.household import EffectivePolicy, InternetPolicy


POLICY_BUNDLE_SCHEMA: Final = "home-center.household-policy-bundle.v1"
POLICY_COMPOSITION_PREVIEW_SCHEMA: Final = "home-center.household-policy-composition-preview.v1"
MAX_POLICY_BUNDLE_NAME = 80
MAX_POLICY_BUNDLES = 64

_CAPABILITY_FIELDS: Final = (
    "vpn_allowed",
    "home_files_allowed",
    "smart_home_control_allowed",
    "administration_allowed",
)
_INTERNET_RESTRICTIVENESS: Final = {
    InternetPolicy.FULL: 0,
    InternetPolicy.FILTERED: 1,
    InternetPolicy.GUEST: 2,
}


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    """A reusable fail-closed set of household policy restrictions.

    The first 0.59 slice deliberately permits only monotonic restrictions. A bundle
    cannot grant a capability that the role-derived EffectivePolicy does not already
    have, cannot weaken managed-device requirements, and cannot enable external
    publication or production mutation.
    """

    bundle_id: str
    display_name: str
    internet_policy: InternetPolicy | None = None
    vpn_allowed: bool | None = None
    managed_device_required: bool | None = None
    home_files_allowed: bool | None = None
    smart_home_control_allowed: bool | None = None
    administration_allowed: bool | None = None
    schema: str = field(default=POLICY_BUNDLE_SCHEMA, init=False)
    external_publication_allowed: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "bundle_id", _identifier(self.bundle_id, "invalid_policy_bundle_id"))
        name = self.display_name.strip() if isinstance(self.display_name, str) else ""
        if not name or len(name) > MAX_POLICY_BUNDLE_NAME or any(ord(char) < 32 for char in name):
            raise HomeServiceCatalogError("invalid_policy_bundle_name")
        object.__setattr__(self, "display_name", name)

        if self.internet_policy is not None and not isinstance(self.internet_policy, InternetPolicy):
            raise HomeServiceCatalogError("invalid_policy_bundle_internet_policy")
        for field_name in (
            "vpn_allowed",
            "managed_device_required",
            "home_files_allowed",
            "smart_home_control_allowed",
            "administration_allowed",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, bool):
                raise HomeServiceCatalogError("invalid_policy_bundle_value")

        if all(
            value is None
            for value in (
                self.internet_policy,
                self.vpn_allowed,
                self.managed_device_required,
                self.home_files_allowed,
                self.smart_home_control_allowed,
                self.administration_allowed,
            )
        ):
            raise HomeServiceCatalogError("empty_policy_bundle")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "bundle_id": self.bundle_id,
            "display_name": self.display_name,
            "internet_policy": self.internet_policy.value if self.internet_policy is not None else None,
            "vpn_allowed": self.vpn_allowed,
            "managed_device_required": self.managed_device_required,
            "home_files_allowed": self.home_files_allowed,
            "smart_home_control_allowed": self.smart_home_control_allowed,
            "administration_allowed": self.administration_allowed,
            "external_publication_allowed": False,
            "production_mutation_enabled": False,
        }


@dataclass(frozen=True, slots=True)
class PolicyChange:
    field: str
    before: str | bool
    after: str | bool
    code: str = field(default="restriction_applied", init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "field": self.field,
            "before": self.before,
            "after": self.after,
            "code": self.code,
        }


@dataclass(frozen=True, slots=True)
class PolicyCompositionPreview:
    preview_id: str
    base_policy_id: str
    bundle_ids: tuple[str, ...]
    effective_policy: EffectivePolicy
    changes: tuple[PolicyChange, ...]
    schema: str = field(default=POLICY_COMPOSITION_PREVIEW_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "preview_id": self.preview_id,
            "base_policy_id": self.base_policy_id,
            "bundle_ids": list(self.bundle_ids),
            "effective_policy": self.effective_policy.to_dict(),
            "changes": [change.to_dict() for change in self.changes],
            "confirmation_required": True,
            "mutation_authorized": False,
            "production_mutation_enabled": False,
        }


def _validate_bundle_against_base(base: EffectivePolicy, bundle: PolicyBundle) -> None:
    if bundle.internet_policy is not None:
        if _INTERNET_RESTRICTIVENESS[bundle.internet_policy] < _INTERNET_RESTRICTIVENESS[base.internet_policy]:
            raise HomeServiceCatalogError("policy_bundle_privilege_escalation")

    for field_name in _CAPABILITY_FIELDS:
        requested = getattr(bundle, field_name)
        if requested is True and getattr(base, field_name) is False:
            raise HomeServiceCatalogError("policy_bundle_privilege_escalation")

    if bundle.managed_device_required is False and base.managed_device_required is True:
        raise HomeServiceCatalogError("policy_bundle_privilege_escalation")


def _effective_policy_id(
    *,
    base: EffectivePolicy,
    internet_policy: InternetPolicy,
    vpn_allowed: bool,
    managed_device_required: bool,
    home_files_allowed: bool,
    smart_home_control_allowed: bool,
    administration_allowed: bool,
) -> str:
    canonical = {
        "household_id": base.household_id,
        "member_id": base.member_id,
        "role": base.role.value,
        "internet_policy": internet_policy.value,
        "vpn_allowed": vpn_allowed,
        "managed_device_required": managed_device_required,
        "home_files_allowed": home_files_allowed,
        "smart_home_control_allowed": smart_home_control_allowed,
        "administration_allowed": administration_allowed,
        "external_publication_allowed": False,
        "production_mutation_enabled": False,
    }
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return "hpol-" + hashlib.sha256(encoded).hexdigest()[:24]


def compose_policy_bundles(
    base: EffectivePolicy,
    bundles: Iterable[PolicyBundle],
) -> PolicyCompositionPreview:
    """Build an order-independent, non-mutating EffectivePolicy preview.

    Bundle composition is an intersection of authority: capability grants can only
    be removed, managed-device requirements can only be added, and internet access
    can only become more restrictive.
    """

    if not isinstance(base, EffectivePolicy):
        raise TypeError("invalid_effective_policy")
    if base.external_publication_allowed or base.production_mutation_enabled:
        raise HomeServiceCatalogError("unsafe_effective_policy_base")

    values = tuple(bundles)
    if not values:
        raise HomeServiceCatalogError("policy_bundle_required")
    if len(values) > MAX_POLICY_BUNDLES:
        raise HomeServiceCatalogError("too_many_policy_bundles")
    if any(not isinstance(bundle, PolicyBundle) for bundle in values):
        raise TypeError("invalid_policy_bundle")
    ordered = tuple(sorted(values, key=lambda bundle: bundle.bundle_id))
    bundle_ids = tuple(bundle.bundle_id for bundle in ordered)
    if len(bundle_ids) != len(set(bundle_ids)):
        raise HomeServiceCatalogError("duplicate_policy_bundle")

    for bundle in ordered:
        _validate_bundle_against_base(base, bundle)

    requested_internet = [
        bundle.internet_policy for bundle in ordered if bundle.internet_policy is not None
    ]
    internet_policy = max(
        (base.internet_policy, *requested_internet),
        key=lambda value: _INTERNET_RESTRICTIVENESS[value],
    )

    capabilities: dict[str, bool] = {}
    for field_name in _CAPABILITY_FIELDS:
        current = getattr(base, field_name)
        restrictions = [
            value
            for bundle in ordered
            if (value := getattr(bundle, field_name)) is not None
        ]
        capabilities[field_name] = current and all(restrictions) if restrictions else current

    managed_requests = [
        bundle.managed_device_required
        for bundle in ordered
        if bundle.managed_device_required is not None
    ]
    managed_device_required = (
        base.managed_device_required or any(managed_requests)
        if managed_requests
        else base.managed_device_required
    )

    effective = EffectivePolicy(
        policy_id=_effective_policy_id(
            base=base,
            internet_policy=internet_policy,
            vpn_allowed=capabilities["vpn_allowed"],
            managed_device_required=managed_device_required,
            home_files_allowed=capabilities["home_files_allowed"],
            smart_home_control_allowed=capabilities["smart_home_control_allowed"],
            administration_allowed=capabilities["administration_allowed"],
        ),
        household_id=base.household_id,
        member_id=base.member_id,
        role=base.role,
        internet_policy=internet_policy,
        vpn_allowed=capabilities["vpn_allowed"],
        managed_device_required=managed_device_required,
        home_files_allowed=capabilities["home_files_allowed"],
        smart_home_control_allowed=capabilities["smart_home_control_allowed"],
        administration_allowed=capabilities["administration_allowed"],
        external_publication_allowed=False,
    )

    changes: list[PolicyChange] = []
    for field_name in (
        "internet_policy",
        "vpn_allowed",
        "managed_device_required",
        "home_files_allowed",
        "smart_home_control_allowed",
        "administration_allowed",
    ):
        before = getattr(base, field_name)
        after = getattr(effective, field_name)
        if before == after:
            continue
        before_value = before.value if isinstance(before, InternetPolicy) else before
        after_value = after.value if isinstance(after, InternetPolicy) else after
        changes.append(PolicyChange(field=field_name, before=before_value, after=after_value))

    preview_canonical = {
        "base_policy_id": base.policy_id,
        "bundle_ids": bundle_ids,
        "effective_policy_id": effective.policy_id,
        "changes": [change.to_dict() for change in changes],
    }
    encoded = json.dumps(
        preview_canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    preview_id = "hppv-" + hashlib.sha256(encoded).hexdigest()[:24]

    return PolicyCompositionPreview(
        preview_id=preview_id,
        base_policy_id=base.policy_id,
        bundle_ids=bundle_ids,
        effective_policy=effective,
        changes=tuple(changes),
    )


def compose_policy_bundle(base: EffectivePolicy, bundle: PolicyBundle) -> PolicyCompositionPreview:
    """Convenience wrapper for composing exactly one policy bundle."""

    return compose_policy_bundles(base, (bundle,))
