from __future__ import annotations

import json
import unittest
from pathlib import Path

from home_center.home_services import (
    BUILTIN_HOME_SERVICES,
    HOME_SERVICE_BY_ID,
    BackupPolicy,
    HomeServiceCatalog,
    HomeServiceCatalogError,
    HomeServiceKind,
    HomeServiceProfile,
    PublicationPolicy,
    REQUIRED_LIFECYCLE,
)


ROOT = Path(__file__).resolve().parents[1]


class HomeServiceCatalogTests(unittest.TestCase):
    def test_builtin_catalog_covers_accepted_home_services(self) -> None:
        self.assertEqual(
            {
                "android-mdm",
                "minecraft-server",
                "torrent-client",
                "torrserver",
                "yandex-smart-home",
                "zigbee-bridge",
            },
            set(HOME_SERVICE_BY_ID),
        )
        value = BUILTIN_HOME_SERVICES.to_dict()
        self.assertEqual("home-center.home-service-catalog.v1", value["schema"])
        self.assertIs(value["production_mutation_enabled"], False)
        self.assertEqual(sorted(HOME_SERVICE_BY_ID), [row["service_id"] for row in value["profiles"]])
        self.assertTrue(all(tuple(row["lifecycle"]) == REQUIRED_LIFECYCLE for row in value["profiles"]))

    def test_publication_is_never_implicit(self) -> None:
        for profile in BUILTIN_HOME_SERVICES.profiles:
            self.assertIn(profile.publication_policy, {PublicationPolicy.LOCAL_ONLY, PublicationPolicy.EXPLICIT})
        self.assertEqual(PublicationPolicy.LOCAL_ONLY, HOME_SERVICE_BY_ID["torrent-client"].publication_policy)
        self.assertEqual(PublicationPolicy.LOCAL_ONLY, HOME_SERVICE_BY_ID["zigbee-bridge"].publication_policy)

    def test_catalog_rejects_duplicate_and_noncanonical_profiles(self) -> None:
        first = BUILTIN_HOME_SERVICES.profiles[0]
        with self.assertRaisesRegex(HomeServiceCatalogError, "duplicate_service_id"):
            HomeServiceCatalog((first, first))
        with self.assertRaisesRegex(HomeServiceCatalogError, "noncanonical_profile_order"):
            HomeServiceCatalog(tuple(reversed(BUILTIN_HOME_SERVICES.profiles)))

    def test_profile_rejects_unsafe_or_incomplete_contracts(self) -> None:
        with self.assertRaisesRegex(HomeServiceCatalogError, "invalid_lifecycle"):
            HomeServiceProfile(
                "service-a",
                HomeServiceKind.TORRSERVER,
                "Service A",
                ("runtime.container.v1",),
                ("media.stream.v1",),
                4,
                PublicationPolicy.EXPLICIT,
                BackupPolicy.STATE,
                ("install", "remove"),
            )
        with self.assertRaisesRegex(HomeServiceCatalogError, "invalid_required_capabilities"):
            HomeServiceProfile(
                "service-a",
                HomeServiceKind.TORRSERVER,
                "Service A",
                ("runtime.container.v1", "runtime.container.v1"),
                (),
                4,
                PublicationPolicy.EXPLICIT,
                BackupPolicy.STATE,
            )

    def test_catalog_contract_is_closed_and_inert(self) -> None:
        contract = json.loads(
            (ROOT / "contracts/market/home-service-profile.v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertIs(contract["additionalProperties"], False)
        self.assertIs(contract["properties"]["production_mutation_enabled"]["const"], False)
        self.assertIs(contract["$defs"]["profile"]["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
