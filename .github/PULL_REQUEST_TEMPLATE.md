## Module

<!-- e.g. M3 RSA-OAEP key management -->

## What changed

## How it was tested

- [ ] `pytest` passes locally
- [ ] `npm test` passes locally (if frontend touched)
- [ ] Added happy-path **and** negative/attack tests

## Security checklist

- [ ] No secrets, keys, passwords or tokens in code, tests or logs
- [ ] Follows docs/security-design.md (or this PR updates it)
- [ ] API changes reflected in docs/api-contracts.md and tests/test_api_contract.py
- [ ] Security-relevant actions call `audit.service.record_event` (denials recorded before raising)
- [ ] Routes use `db: DbSession`; no `commit()` in services; errors are raised, not returned
- [ ] Removed implemented endpoints from tests/test_not_implemented.py
- [ ] `MODULE_INFO.implemented` set to True only if every endpoint works and is tested
- [ ] Migration added for model changes; `alembic heads` shows a single head
