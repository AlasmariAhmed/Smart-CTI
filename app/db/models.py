"""SQLAlchemy ORM models for the CTI store.

Schema notes
------------
* `iocs` is the canonical IOC table. Dedup key = (type, value).
* Same IOC seen from multiple feeds → one `iocs` row, many `ioc_sources` rows.
  This preserves corroboration evidence (multi-source = stronger signal).
* `scoring_reasons` is the audit trail. Analysts must be able to answer
  "why is this 73?" by reading these rows back.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_ioc_type_value"),
        Index("ix_ioc_value", "value"),
        Index("ix_ioc_score", "relevance_score"),
        Index("ix_ioc_type", "type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)

    first_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    relevance_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)

    threat_actor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    malware_family: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cve: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    sources: Mapped[list["IOCSource"]] = relationship(
        "IOCSource", back_populates="ioc", cascade="all, delete-orphan"
    )
    tags: Mapped[list["IOCTag"]] = relationship(
        "IOCTag", back_populates="ioc", cascade="all, delete-orphan"
    )
    reasons: Mapped[list["ScoringReason"]] = relationship(
        "ScoringReason", back_populates="ioc", cascade="all, delete-orphan"
    )


class IOCSource(Base):
    __tablename__ = "ioc_sources"
    __table_args__ = (Index("ix_ioc_sources_ioc_id", "ioc_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"))
    source_name: Mapped[str] = mapped_column(String(64), nullable=False)
    source_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    raw_context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    ioc: Mapped["IOC"] = relationship("IOC", back_populates="sources")


class IOCTag(Base):
    __tablename__ = "ioc_tags"
    __table_args__ = (
        UniqueConstraint("ioc_id", "tag", name="uq_ioc_tag"),
        Index("ix_ioc_tags_tag", "tag"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"))
    tag: Mapped[str] = mapped_column(String(128), nullable=False)

    ioc: Mapped["IOC"] = relationship("IOC", back_populates="tags")


class ScoringReason(Base):
    __tablename__ = "scoring_reasons"
    __table_args__ = (Index("ix_scoring_reasons_ioc_id", "ioc_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"))
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    ioc: Mapped["IOC"] = relationship("IOC", back_populates="reasons")


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    aliases: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON-encoded list
    known_targeting: Mapped[bool] = mapped_column(Boolean, default=False)


class FeedRun(Base):
    __tablename__ = "feed_runs"
    __table_args__ = (Index("ix_feed_runs_connector", "connector_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    connector_name: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    iocs_pulled: Mapped[int] = mapped_column(Integer, default=0)
    iocs_stored: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running/success/error
