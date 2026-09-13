from __future__ import annotations

import inspect

import pytest

from home_center.api_v10 import RuntimeRequestHandlerV10
from home_center.api_v11 import RuntimeRequestHandlerV11
from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding_effect_api import QrOnboardingEffectApiError


def _snapshot():
    households = HouseholdStore()
    households.create(
        Household(
            household_id="home-main",
            members=(
                FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
                FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
            ),
            devices=(),
        )
    )
    return households.read("home-main")


def test_effect_routes_extend_v10_without_shadowing_invitation_routes() -> None:
    assert issubclass(RuntimeRequestHandlerV11, RuntimeRequestHandlerV10)
    assert RuntimeRequestHandlerV11.QR_EFFECT_ADMIT_POSTS == {
        "/api/v1/household/qr-onboarding/effect/admit"
    }
    assert RuntimeRequestHandlerV11.QR_EFFECT_RUN_POSTS == {
        "/api/v1/household/qr-onboarding/effect/run"
    }
    assert RuntimeRequestHandlerV11.QR_EFFECT_POSTS.isdisjoint(RuntimeRequestHandlerV10.QR_POSTS)


def test_effect_http_boundary_reuses_auth_origin_external_and_bounded_body_fences() -> None:
    source = inspect.getsource(RuntimeRequestHandlerV11.do_POST)
    assert "self._classify_request(correlation_id)" in source
    assert "self._blocked_for_external(path, context)" in source
    assert "self._same_origin_post_allowed(context)" in source
    assert "self._require_actor(correlation_id)" in source
    assert "self._read_json(max_bytes=4096)" in source
    assert "self.runtime.household._actor_member(actor, bindings)" in source
    assert "self._require_parent(snapshot, actor_member_id)" in source
    assert "service.admit(" in source
    assert "service.run(" in source
    assert "int(time.time())" in source
    assert "handoff" not in source
    assert "onboarding_code" not in source


def test_effect_http_requires_enabled_parent_authority() -> None:
    snapshot = _snapshot()
    RuntimeRequestHandlerV11._require_parent(snapshot, "parent-1")
    with pytest.raises(QrOnboardingEffectApiError, match="qr_effect_http_parent_required"):
        RuntimeRequestHandlerV11._require_parent(snapshot, "guest-1")
    with pytest.raises(QrOnboardingEffectApiError, match="qr_effect_http_actor_member_unavailable"):
        RuntimeRequestHandlerV11._require_parent(snapshot, "missing-member")
