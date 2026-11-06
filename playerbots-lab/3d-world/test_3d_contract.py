#!/usr/bin/env python3
"""Source-level regression checks for the isolated 3D lab (not a gameplay test)."""
from pathlib import Path
import unittest

HTML = Path(__file__).resolve().parent / "index.html"

class ThreeDContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = HTML.read_text(encoding="utf-8")

    def test_real_webgl_renderer_not_2d_canvas(self):
        self.assertIn("new THREE.WebGLRenderer(", self.source)
        self.assertIn("new THREE.PerspectiveCamera(", self.source)
        self.assertIn("renderer.render(scene,camera)", self.source)

    def test_terrain_geometry_and_height(self):
        self.assertIn("new THREE.PlaneGeometry(", self.source)
        self.assertIn("geo.computeVertexNormals()", self.source)
        self.assertIn("character.position.y=height(", self.source)

    def test_mobile_controls_and_resize(self):
        for token in ("pointerdown", "pointercancel", "lostpointercapture", "setPointerCapture", "addEventListener('resize'"):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

    def test_no_false_game_connection(self):
        self.assertIn("AUTH/GAME yok", self.source)
        self.assertNotIn("new WebSocket(", self.source)

    def test_lighting_and_shadows(self):
        for token in ("THREE.HemisphereLight", "THREE.DirectionalLight", "shadowMap.enabled=true", "terrain.receiveShadow=true"):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

if __name__ == "__main__":
    unittest.main()
