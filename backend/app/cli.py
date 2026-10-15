"""Operator commands. Run from backend/:  python -m app.cli <command> ...

  promote-admin EMAIL [--yes]   give an existing, active, unlocked account the admin role
  demote-admin EMAIL [--yes]    return an admin to the normal user role

Without --yes the command only shows the matched account and changes nothing.
There is deliberately no command that creates users or touches passwords: accounts are
created only through M1's registration, so every password is Argon2id-hashed.

Exit codes: 0 done / nothing to do, 1 refused (unknown, inactive, locked, last admin),
2 confirmation needed (re-run with --yes).
"""

import argparse
import sys
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import session_scope
from app.models import User
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn
from app.schemas.common import normalize_email


def _is_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:  # SQLite returns naive datetimes; stored as UTC
        locked_until = locked_until.replace(tzinfo=UTC)
    return locked_until > datetime.now(UTC)


def _describe(user: User) -> str:
    state = "active" if user.is_active else "INACTIVE"
    if _is_locked(user):
        state += ", LOCKED"
    return (
        f"  id:       {user.id}\n  username: {user.username}\n  email:    {user.email}\n"
        f"  role:     {user.role}\n  status:   {state}"
    )


def _refusal(db: Session, user: User, new_role: str) -> str | None:
    if new_role == "admin":
        if not user.is_active:
            return "the account is inactive"
        if _is_locked(user):
            return "the account is locked"
    elif user.role == "admin":
        admins = db.scalar(
            select(func.count()).select_from(User).where(User.role == "admin", User.is_active)
        )
        if admins <= 1 and user.is_active:
            return "it is the last active admin"
    return None


def _set_role(email: str, new_role: str, confirmed: bool) -> int:
    with session_scope() as db:
        user = db.scalar(select(User).where(User.email == normalize_email(email)))
        if user is None:
            print(f"No account with email {normalize_email(email)!r}.", file=sys.stderr)
            print("Register it through the application first.", file=sys.stderr)
            return 1

        print("Matched account:\n" + _describe(user))
        if user.role == new_role:
            print(f"No change: the account already has role {new_role!r}.")
            return 0
        reason = _refusal(db, user, new_role)
        if reason:
            print(f"Refused: {reason}.", file=sys.stderr)
            return 1
        if not confirmed:
            print(f"Would change role {user.role!r} -> {new_role!r}. Re-run with --yes to confirm.")
            return 2

        previous, user.role = user.role, new_role
        audit_service.record_event(
            db,
            AuditEventIn(
                event_type="user.role_change",
                resource_type="user",
                resource_id=str(user.id),
                details={"from": previous, "to": new_role, "via": "cli"},
            ),
        )
        # session_scope commits the change and its audit event together on exit.
    print(f"Done: role {previous!r} -> {new_role!r}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("promote-admin", "give an existing account the admin role"),
        ("demote-admin", "return an admin to the normal user role"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("email")
        p.add_argument("--yes", action="store_true", help="apply the change (default: dry run)")

    args = parser.parse_args(argv)
    new_role = "admin" if args.command == "promote-admin" else "user"
    return _set_role(args.email, new_role, args.yes)


if __name__ == "__main__":
    raise SystemExit(main())
