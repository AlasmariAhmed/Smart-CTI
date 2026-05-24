"""Connector registry. Adding a connector = adding it to `ALL_CONNECTORS`."""
from __future__ import annotations

from app.connectors.abusech_feodo import FeodoTrackerConnector
from app.connectors.abusech_malwarebazaar import MalwareBazaarConnector
from app.connectors.abusech_threatfox import ThreatFoxConnector
from app.connectors.abusech_urlhaus import URLhausConnector
from app.connectors.base import BaseConnector
from app.connectors.circl_misp import CIRCLMISPConnector
from app.connectors.emerging_threats import EmergingThreatsConnector
from app.connectors.otx import OTXConnector
from app.connectors.spamhaus_drop import SpamhausDROPConnector


ALL_CONNECTORS: list[type[BaseConnector]] = [
    ThreatFoxConnector,
    URLhausConnector,
    MalwareBazaarConnector,
    FeodoTrackerConnector,
    OTXConnector,
    SpamhausDROPConnector,
    EmergingThreatsConnector,
    CIRCLMISPConnector,
]


def get_connector(name: str) -> BaseConnector | None:
    for cls in ALL_CONNECTORS:
        if cls.name == name:
            return cls()
    return None


def all_enabled_connectors() -> list[BaseConnector]:
    return [cls() for cls in ALL_CONNECTORS if cls().enabled]


def all_connector_names() -> list[str]:
    return [cls.name for cls in ALL_CONNECTORS]
