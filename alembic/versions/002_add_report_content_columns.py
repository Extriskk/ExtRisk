"""Add report_json and report_html to scan_results (store reports in DB)

Revision ID: 002
Revises: 001
Create Date: 2026-02-23

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_results",
        sa.Column("report_json", sa.Text(), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("report_html", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_results", "report_html")
    op.drop_column("scan_results", "report_json")
