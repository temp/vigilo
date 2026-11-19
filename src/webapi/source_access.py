"""Turn a repository's stored credential into what ``git`` needs to clone it.

* GitLab: the decrypted access token, sent as ``oauth2:<token>``.
* GitHub (github.com / GitHub Enterprise Server), sent as ``x-access-token:<token>``:
  a personal access token as stored (``github_token``), or a short-lived installation
  token minted from a stored GitHub App credential (``github_app``).

Callers run :func:`src.webapi.credential_guard.validate_source_credential` first.
"""
from __future__ import annotations

from src.webapi.settings import get_settings


def clone_username(source_type: str) -> str:
    if source_type == "github":
        from src.webapi.github_app import CLONE_USERNAME
        return CLONE_USERNAME
    return "oauth2"


def resolve_clone_token(cred, source_type: str, repo_url: str) -> str | None:
    """The secret ``git`` authenticates with for this source, or None without a
    credential. Blocking (GitHub makes HTTP calls): run it off the event loop."""
    if cred is None:
        return None
    from src.webapi.security.vault import build_vault
    secret = build_vault(get_settings()).decrypt(cred.secret_enc)
    if source_type == "github" and cred.kind == "github_app":
        from src.webapi.github_app import installation_token
        return installation_token(secret, repo_url)
    return secret
