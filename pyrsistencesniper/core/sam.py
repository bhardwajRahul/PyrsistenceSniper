"""Shared SAM account helpers used by more than one account-persistence check."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pyrsistencesniper.core.registry import RegistryNode

if TYPE_CHECKING:
    from pyrsistencesniper.core.context import AnalysisContext

logger = logging.getLogger(__name__)

USERS_PATH = r"SAM\Domains\Account\Users"
USER_LIST_KEY = r"Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
USER_LIST_REPORT_KEY = rf"HKLM\SOFTWARE\{USER_LIST_KEY}"

_HIDDEN_FROM_SIGN_IN = 0


def iter_user_rid_nodes(tree: RegistryNode) -> list[tuple[str, int, RegistryNode]]:
    """Yield (rid_hex, actual_rid, node) for each valid user subkey."""
    results: list[tuple[str, int, RegistryNode]] = []
    for rid_hex_name, child_node in tree.children():
        if rid_hex_name == "Names":
            continue
        try:
            actual_rid = int(rid_hex_name, 16)
        except ValueError:
            logger.debug("Invalid RID hex value: %s", rid_hex_name, exc_info=True)
            continue
        results.append((rid_hex_name, actual_rid, child_node))
    return results


def hides_account(entry_value: object) -> bool:
    """Report whether a UserList entry is the zero that hides the account."""
    # Any other setting leaves the account on the sign-in screen, so it is not a
    # benign instance of the technique but no instance of it at all.
    return isinstance(entry_value, int) and entry_value == _HIDDEN_FROM_SIGN_IN


def iter_hidden_accounts(context: AnalysisContext) -> list[str]:
    """Yield the accounts SpecialAccounts hides, named as the hive spells them."""
    user_list = context.load_subtree("SOFTWARE", USER_LIST_KEY)
    if user_list is None:
        return []
    return [
        account_name
        for account_name, entry_value in user_list.values()
        if account_name and hides_account(entry_value)
    ]


def hidden_account_names(context: AnalysisContext) -> set[str]:
    """Return the casefolded names SpecialAccounts hides from the sign-in screen."""
    # Casefolded for callers that match these against SAM account names,
    # which the UserList entry need not agree with on case.
    return {name.casefold() for name in iter_hidden_accounts(context)}
