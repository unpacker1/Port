#!/usr/bin/env python3
"""Offline mini-RPG HTML smoke checks; no external dependencies."""
from html.parser import HTMLParser
from pathlib import Path
import subprocess
import tempfile
import unittest

HTML = Path(__file__).with_name("index.html")

class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.scripts = []
        self.in_script = False
    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if "id" in d:
            self.ids.add(d["id"])
        if tag == "script":
            self.in_script = True
    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False
    def handle_data(self, data):
        if self.in_script:
            self.scripts.append(data)

class OfflineGameSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = HTML.read_text(encoding="utf-8")
        cls.page = Page()
        cls.page.feed(cls.html)
        cls.js = "\n".join(cls.page.scripts)

    def test_controls_exist(self):
        self.assertTrue({"game", "stats", "pad", "attack", "talk", "potion", "reset", "msg"} <= self.page.ids)

    def test_offline_no_external_dependencies(self):
        self.assertNotIn("<script src=", self.html)
        self.assertNotIn("fetch(", self.js)
        self.assertNotIn("WebSocket(", self.js)

    def test_touch_keys_normalized(self):
        self.assertIn("b.dataset.key.toLowerCase()", self.js)
        self.assertIn('keys.has("arrowup")', self.js)

    def test_gameplay_mechanics(self):
        for name in ("function attack()", "function talk()", "function potion()", "function reset()", "function spawn()", "requestAnimationFrame(tick)", "localStorage.setItem"):
            with self.subTest(name=name):
                self.assertIn(name, self.js)

    def test_javascript_syntax(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "game.js"
            path.write_text(self.js, encoding="utf-8")
            p = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)

if __name__ == "__main__":
    unittest.main(verbosity=2)
