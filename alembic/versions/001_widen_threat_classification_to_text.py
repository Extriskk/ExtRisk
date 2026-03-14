"""Widen threat_classification to TEXT for JSON storage

Revision ID: 001
Revises: None
Create Date: 2026-02-23

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "scan_results",
        "threat_classification",
        existing_type=sa.String(128),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "scan_results",
        "threat_classification",
        existing_type=sa.Text(),
        type_=sa.String(128),
        existing_nullable=True,
    )
