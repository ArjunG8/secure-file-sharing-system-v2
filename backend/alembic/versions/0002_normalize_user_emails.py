"""Normalize user emails and enforce it, making email uniqueness case-insensitive.

Safe on existing data: if two accounts differ only by email case/whitespace, the
migration stops WITHOUT changing anything and lists them, so a person can decide which
account to keep. Otherwise it lowercases/trims stored emails, then adds the CHECK.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-15
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NORMALIZED = "email = lower(trim(email))"


def upgrade() -> None:
    conn = op.get_bind()
    duplicates = conn.execute(
        sa.text(
            "SELECT lower(trim(email)) AS normalized, count(*) AS n FROM users "
            "GROUP BY lower(trim(email)) HAVING count(*) > 1"
        )
    ).all()
    if duplicates:
        listing = ", ".join(f"{row.normalized} ({row.n} accounts)" for row in duplicates)
        raise RuntimeError(
            "Cannot normalize emails: these addresses belong to several accounts that "
            f"differ only by case/whitespace: {listing}. Resolve them manually, then rerun."
        )

    conn.execute(
        sa.text("UPDATE users SET email = lower(trim(email)) WHERE email <> lower(trim(email))")
    )
    with op.batch_alter_table("users") as batch_op:
        batch_op.create_check_constraint(op.f("ck_users_email_normalized"), NORMALIZED)


def downgrade() -> None:
    # Emails stay lowercased; only the enforcement is removed.
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint(op.f("ck_users_email_normalized"), type_="check")
