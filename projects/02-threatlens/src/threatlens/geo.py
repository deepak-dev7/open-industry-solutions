"""Offline Geo-IP resolution and Haversine geo-velocity anomaly calculation."""

from __future__ import annotations

import ipaddress
import math
from typing import NamedTuple

# Embedded offline IP subnet to city/coordinates mapping for common attack source pools
# Real IP ranges (e.g. Tor exit nodes, major cloud datacenters, and demo geographic anchors)
class GeoLocation(NamedTuple):
    country: str
    city: str
    lat: float
    lon: float

# Internal / private IP fallback
LOCAL_GEO = GeoLocation(country="Private Network", city="Internal LAN", lat=0.0, lon=0.0)

# Well-known reference locations for deterministic test scenarios and offline resolution
SUBNET_GEO_MAP: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, GeoLocation]] = [
    (ipaddress.ip_network("185.220.101.0/24"), GeoLocation("Germany", "Frankfurt", 50.1109, 8.6821)),
    (ipaddress.ip_network("185.220.102.0/24"), GeoLocation("Netherlands", "Amsterdam", 52.3676, 4.9041)),
    (ipaddress.ip_network("198.51.100.0/24"), GeoLocation("United States", "New York", 40.7128, -74.0060)),
    (ipaddress.ip_network("203.0.113.0/24"), GeoLocation("Japan", "Tokyo", 35.6762, 139.6503)),
    (ipaddress.ip_network("192.0.2.0/24"), GeoLocation("United Kingdom", "London", 51.5074, -0.1278)),
    (ipaddress.ip_network("45.154.255.0/24"), GeoLocation("Russia", "Moscow", 55.7558, 37.6173)),
    (ipaddress.ip_network("103.251.167.0/24"), GeoLocation("Singapore", "Singapore", 1.3521, 103.8198)),
    (ipaddress.ip_network("104.244.72.0/24"), GeoLocation("United States", "San Francisco", 37.7749, -122.4194)),
    (ipaddress.ip_network("194.26.29.0/24"), GeoLocation("Seychelles", "Victoria", -4.6191, 55.4513)),
    (ipaddress.ip_network("162.158.0.0/16"), GeoLocation("United States", "Chicago", 41.8781, -87.6298)),
    (ipaddress.ip_network("140.82.112.0/20"), GeoLocation("United States", "Seattle", 47.6062, -122.3321)),
]


def resolve_ip_geo(ip_str: str) -> GeoLocation:
    """Resolve an IP address to offline geographic coordinates without external network calls."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return GeoLocation("Invalid IP", "Unknown", 0.0, 0.0)

    for subnet, geo in SUBNET_GEO_MAP:
        if ip in subnet:
            return geo

    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
        return LOCAL_GEO

    # Deterministic pseudo-geo based on IP octets for arbitrary public test IPs
    # Maps predictably into major internet traffic hubs
    octets = [int(p) for p in ip.exploded.replace(":", "").split(".")[:4]] if "." in str(ip) else [10, 20, 30, 40]
    hubs = [
        GeoLocation("United States", "Ashburn", 39.0438, -77.4874),
        GeoLocation("United Kingdom", "London", 51.5074, -0.1278),
        GeoLocation("Germany", "Frankfurt", 50.1109, 8.6821),
        GeoLocation("Japan", "Tokyo", 35.6762, 139.6503),
        GeoLocation("Singapore", "Singapore", 1.3521, 103.8198),
        GeoLocation("Australia", "Sydney", -33.8688, 151.2093),
        GeoLocation("Brazil", "Sao Paulo", -23.5505, -46.6333),
        GeoLocation("India", "Mumbai", 19.0760, 72.8777),
    ]
    idx = (octets[0] + octets[-1]) % len(hubs)
    return hubs[idx]


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points on the Earth in kilometers."""
    if lat1 == lat2 and lon1 == lon2:
        return 0.0

    r = 6371.0  # Earth's radius in kilometers
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (math.sin(delta_phi / 2.0) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2)
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


def calculate_velocity_kmh(
    lat1: float, lon1: float, time_sec1: float,
    lat2: float, lon2: float, time_sec2: float
) -> tuple[float, float]:
    """Return (distance_km, velocity_kmh) between two geographical observations."""
    distance = haversine_distance_km(lat1, lon1, lat2, lon2)
    time_diff_hours = abs(time_sec2 - time_sec1) / 3600.0

    if time_diff_hours <= 0.0001:  # Near instantaneous
        return distance, 999999.0 if distance > 10.0 else 0.0

    velocity = distance / time_diff_hours
    return distance, velocity
