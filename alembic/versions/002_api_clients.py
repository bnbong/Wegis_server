"""Add api_clients table (per-install auth)

Revision ID: 002
Revises: 001
Create Date: 2026-06-22 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Must match the ORM model (src/orm_models.py: APIClient).
    op.create_table(
        "api_clients",
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("install_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("ext_version", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("token_hash"),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_api_clients_status"
        ),
    )
    op.create_index(
        op.f("ix_api_clients_install_id"), "api_clients", ["install_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_api_clients_install_id"), table_name="api_clients")
    op.drop_table("api_clients")
