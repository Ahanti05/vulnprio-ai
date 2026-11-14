"""Map attack steps and findings to MITRE ATT&CK (Enterprise) techniques.

Transparent, rule-based mapping (reference: https://attack.mitre.org/):

    Step from the Internet, no user action needed   -> T1190 Exploit Public-Facing Application
    Step that needs a user to act (email, document,
      web page)                                     -> T1203 Exploitation for Client Execution
    Step between internal assets, no user action    -> T1210 Exploitation of Remote Services
    Local-only vulnerability (not a network step)   -> T1068 Exploitation for Privilege Escalation

The mapping describes *how* a modelled step would be carried out; it does not
claim that a real attacker has used it.
"""
from __future__ import annotations

import math

TECHNIQUES = {
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
}

_USER_VALUES = {"REQUIRED", "PASSIVE", "ACTIVE"}   # CVSS v3 / v4 user-interaction values


def needs_user(user_interaction) -> bool:
    if user_interaction is None or (isinstance(user_interaction, float) and math.isnan(user_interaction)):
        return False
    return str(user_interaction).upper() in _USER_VALUES


def technique_for_step(from_internet: bool, user_required: bool) -> str:
    if user_required:
        return "T1203"
    return "T1190" if from_internet else "T1210"


def technique_for_finding(remote: bool, exposure: str, user_interaction) -> str:
    if not remote:
        return "T1068"
    if needs_user(user_interaction):
        return "T1203"
    return "T1190" if str(exposure) == "internet" else "T1210"


def name(tid: str) -> str:
    return TECHNIQUES.get(tid, ("Unknown", ""))[0]


def tactic(tid: str) -> str:
    return TECHNIQUES.get(tid, ("", "Unknown"))[1]


def label(tid: str) -> str:
    return f"{tid} · {name(tid)}"


def url(tid: str) -> str:
    return f"https://attack.mitre.org/techniques/{tid}/"
