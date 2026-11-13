"""Unit tests for offline Geo-IP resolution and Haversine velocity calculations."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threatlens.geo import calculate_velocity_kmh, haversine_distance_km, resolve_ip_geo


class GeoTestCase(unittest.TestCase):
    def test_private_and_loopback_ip_resolution(self) -> None:
        local1 = resolve_ip_geo("127.0.0.1")
        self.assertEqual(local1.country, "Private Network")
        local2 = resolve_ip_geo("10.0.1.55")
        self.assertEqual(local2.country, "Private Network")
        local3 = resolve_ip_geo("192.168.1.100")
        self.assertEqual(local3.country, "Private Network")

    def test_mapped_public_ip_resolution(self) -> None:
        # Tor exit node subnet
        tor = resolve_ip_geo("185.220.101.5")
        self.assertEqual(tor.country, "Germany")
        self.assertEqual(tor.city, "Frankfurt")

        # Tokyo subnet
        tokyo = resolve_ip_geo("203.0.113.88")
        self.assertEqual(tokyo.country, "Japan")
        self.assertEqual(tokyo.city, "Tokyo")

    def test_haversine_distance_calculation(self) -> None:
        # London (51.5074, -0.1278) to Tokyo (35.6762, 139.6503) is ~9560 km
        dist = haversine_distance_km(51.5074, -0.1278, 35.6762, 139.6503)
        self.assertGreater(dist, 9000.0)
        self.assertLess(dist, 10000.0)

        # Same location distance is 0
        self.assertEqual(haversine_distance_km(40.7128, -74.0060, 40.7128, -74.0060), 0.0)

    def test_impossible_travel_velocity_calculation(self) -> None:
        # London to Tokyo in 15 minutes (900 seconds)
        t1 = 1763000000.0
        t2 = t1 + 900.0  # 15 minutes
        dist, velocity = calculate_velocity_kmh(51.5074, -0.1278, t1, 35.6762, 139.6503, t2)
        self.assertGreater(dist, 9000.0)
        self.assertGreater(velocity, 35000.0)  # > 35,000 km/h (clearly impossible)


if __name__ == "__main__":
    unittest.main()
