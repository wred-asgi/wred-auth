"""Initial account, session, credential, and identity tables."""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "wred_auth_users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("password", sa.Text),
        sa.Column("verified", sa.Boolean, nullable=False),
        sa.Column("active", sa.Boolean, nullable=False),
        sa.Column("roles", sa.JSON, nullable=False),
        sa.Column("totp", sa.Text),
        sa.Column("totp_pending", sa.Text),
        sa.Column("totp_step", sa.Integer, nullable=False),
        sa.Column("recovery", sa.JSON, nullable=False),
    )
    op.create_table(
        "wred_auth_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("wred_auth_users.id"),
            nullable=False,
        ),
        sa.Column("created", sa.Float, nullable=False),
        sa.Column("auth_time", sa.Float, nullable=False),
        sa.Column("expires", sa.Float, nullable=False),
        sa.Column("revoked", sa.Boolean, nullable=False),
    )
    op.create_index("ix_wred_auth_sessions_user_id", "wred_auth_sessions", ["user_id"])
    op.create_table(
        "wred_auth_tokens",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(64), sa.ForeignKey("wred_auth_users.id")),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("expires", sa.Float, nullable=False),
        sa.Column("used", sa.Boolean, nullable=False),
        sa.Column("data", sa.JSON, nullable=False),
    )
    op.create_index("ix_wred_auth_tokens_user_id", "wred_auth_tokens", ["user_id"])
    op.create_table(
        "wred_auth_identities",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("wred_auth_users.id"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.UniqueConstraint("provider", "subject"),
    )
    op.create_index(
        "ix_wred_auth_identities_user_id", "wred_auth_identities", ["user_id"]
    )


def downgrade():
    for table in (
        "wred_auth_identities",
        "wred_auth_tokens",
        "wred_auth_sessions",
        "wred_auth_users",
    ):
        op.drop_table(table)
