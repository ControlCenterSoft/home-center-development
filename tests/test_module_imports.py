from __future__ import annotations

import importlib
import unittest
from pathlib import Path


class ModuleImportTests(unittest.TestCase):
    def test_every_home_center_module_imports(self) -> None:
        package_root = Path("product/control-plane/src/home_center")
        modules: list[str] = []
        for path in sorted(package_root.rglob("*.py")):
            relative = path.relative_to(package_root)
            if relative.name == "__main__.py":
                continue
            parts = list(relative.with_suffix("").parts)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            module = "home_center" if not parts else "home_center." + ".".join(parts)
            modules.append(module)
        self.assertTrue(modules)
        for module in modules:
            with self.subTest(module=module):
                importlib.import_module(module)


if __name__ == "__main__":
    unittest.main()
