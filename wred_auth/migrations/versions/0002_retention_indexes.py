"""Indexes for retention cleanup and live account records."""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

INDEXES = (
    ("ix_wred_auth_sessions_expires", "wred_auth_sessions", ["expires"]),
    ("ix_wred_auth_tokens_expires", "wred_auth_tokens", ["expires"]),
    (
        "ix_wred_auth_sessions_live",
        "wred_auth_sessions",
        ["user_id", "revoked", "expires"],
    ),
    (
        "ix_wred_auth_tokens_live",
        "wred_auth_tokens",
        ["user_id", "kind", "used", "expires"],
    ),
)


def upgrade():
    for name, table, columns in INDEXES:
        op.create_index(name, table, columns)


def downgrade():
    for name, table, _ in reversed(INDEXES):
        op.drop_index(name, table_name=table)
