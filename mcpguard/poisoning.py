"""Heuristics for tool poisoning: a description that tries to steer the model.

A tool description should say what the tool does. Poisoned descriptions instead
give the model orders: use another tool first, force a parameter to a literal
value, read a key file, mail a result to an outsider, or "this outranks the
user". These rules look for those orders in the declared text. They are
deliberately explicit patterns, so a determined attacker can rephrase around them.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

_INVISIBLE = {code: None for code in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)}


@dataclass(frozen=True)
class Signal:
    rule: str
    severity: str
    message: str


def normalize(text: str) -> str:
    """Fold look-alike characters and drop zero-width ones that hide keywords."""
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE)


_PRIORITY = re.compile(
    r"priority\s+(?:is\s+)?(?:higher|above|over)|higher\s+priority|"
    r"take[s]?\s+precedence|overrid\w+\s+(?:the\s+)?(?:user|system)|"
    r"supersed\w+\s+(?:the\s+)?(?:user|any)|"
    r"regardless\s+of\s+(?:the\s+)?(?:user|original|intended|query|request)|"
    r"ignore\s+(?:the\s+)?user",
    re.IGNORECASE,
)
_SENSITIVE_PATH = re.compile(
    r"~/\.ssh|\.ssh/|id_rsa|id_ed25519|authorized_keys|known_hosts|/etc/passwd|"
    r"/etc/shadow|\.aws/|\.env\b|\.npmrc|\.netrc|\.git-credentials|\.bash_history|"
    r"private[_ ]key|wallet\.dat|credentials\.json|keychain",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"[\w.+-]+@(?!example\.|test\.|domain\.)[\w-]+\.[\w.-]+")
_SEND_VERB = re.compile(
    r"\b(?:send|forward|email|mail|cc|bcc|notify|alert|report|upload|post|"
    r"transmit|exfiltrat\w+)\b",
    re.IGNORECASE,
)
_MODAL = re.compile(
    r"\b(?:must|always|required\s+to|need\s+to|have\s+to|mandatory|should)\b",
    re.IGNORECASE,
)
_STRONG_MODAL = re.compile(
    r"\b(?:must|always|mandatory|required\s+to)\b", re.IGNORECASE
)
_GOVERNING = re.compile(
    r"\b(?:before|prior\s+to|when(?:ever)?|while|each\s+time|"
    r"for\s+(?:any|every|each|all))\b",
    re.IGNORECASE,
)
_TOOL_REF = re.compile(
    r"[`'\"‘“]([A-Za-z][\w.\-]{2,})[`'\"’”]|"
    r"\b([a-z]+(?:_[a-z0-9]+)+|[a-z]+[A-Z][A-Za-z0-9]+)\b|"
    r"\btool\s+([A-Za-z][\w.\-]{2,})"
)
_NOT_A_TOOL = frozenset(
    [
        "this",
        "that",
        "the",
        "for",
        "and",
        "with",
        "you",
        "your",
        "has",
        "not",
        "can",
        "will",
        "use",
        "used",
        "which",
        "when",
        "only",
        "from",
        "into",
        "each",
        "any",
        "all",
        "its",
        "was",
        "are",
    ]
)
_THREAT = re.compile(
    r"(?:failure|failing|skipping|omitting|not\s+doing)\s+(?:to\s+do\s+so|this|it|to)\b"
    r"|this\s+step\s+is\s+(?:critical|essential|required|necessary)|"
    r"will\s+(?:crash|corrupt|break|disrupt|overload|cause\s+system)",
    re.IGNORECASE,
)
_ORDER = re.compile(r"\b(?:make\s+sure|first|ensure)\b", re.IGNORECASE)
_CALL = re.compile(
    r"\b(?:call|use|invoke|run|trigger|execute|fetch|request|perform|scan|query|"
    r"retrieve)\b",
    re.IGNORECASE,
)
_FORCE_VALUE = re.compile(
    r"\b(?:set|change|modify|replace|override|redirect|append|prepend|add|force|"
    r"substitute|swap)\b[^.]{0,80}?(?:\bto\b|\bwith\b|\bas\b)\s*"
    r"(?:(?:any|the|every|each|all)\s+)?[`'\"‘“]",
    re.IGNORECASE,
)
_PARAMETER = re.compile(
    r"\b(?:set|change|modify|replace|override|redirect|append|add)\b[^.]{0,60}?"
    r"\b(?:parameter|argument|param|query|selector)\b",
    re.IGNORECASE,
)
_PRESSURE = re.compile(
    r"not\s+optional|do\s+not\s+skip|skipping\s+(?:this|it)|failure\s+to|"
    r"will\s+(?:break|fail|disrupt)|mandatory",
    re.IGNORECASE,
)
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


def _canonical(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _other_tool_named(sentence: str, own_name: str, start: int = 0) -> bool:
    own = _canonical(own_name)
    for match in _TOOL_REF.finditer(sentence, start):
        word = match.group(1) or match.group(2) or match.group(3)
        reference = _canonical(word)
        if reference and reference != own and word.lower() not in _NOT_A_TOOL:
            return True
    return False


def _other_tool_governed(sentence: str, own_name: str) -> bool:
    """A clause like "when using 'X'" where X is not this tool."""
    governing = _GOVERNING.search(sentence)
    return governing is not None and _other_tool_named(
        sentence, own_name, governing.end()
    )


def scan_description(name: str, description: str) -> list[Signal]:
    """Return poisoning signals found in one tool description."""
    text = normalize(description)
    signals: list[Signal] = []

    def add(rule: str, severity: str, message: str) -> None:
        signals.append(Signal(rule, severity, message))

    if _PRIORITY.search(text):
        add(
            "priority-override",
            "error",
            "Description claims to outrank the user's request",
        )
    if _SENSITIVE_PATH.search(text):
        add(
            "sensitive-path",
            "error",
            "Description names a credential or key file the tool has no reason to cite",
        )
    if _EMAIL.search(text) and _SEND_VERB.search(text):
        add(
            "exfiltration-target",
            "error",
            "Description tells the model to send data to a fixed address",
        )

    threat = bool(_THREAT.search(text))
    hijack = tamper = mandated_call = False
    for sentence in _SENTENCE.split(text):
        if not sentence.strip():
            continue
        strong = bool(_STRONG_MODAL.search(sentence))
        if _other_tool_governed(sentence, name) and (
            strong
            or threat
            or _ORDER.search(sentence)
            or _MODAL.search(sentence)
            or _FORCE_VALUE.search(sentence)
            or _PARAMETER.search(sentence)
            or _CALL.search(sentence)
        ):
            hijack = True
        if strong and _CALL.search(sentence) and _other_tool_named(sentence, name):
            mandated_call = True
        if strong and (_FORCE_VALUE.search(sentence) or _PARAMETER.search(sentence)):
            tamper = True
    if hijack:
        add(
            "cross-tool-instruction",
            "error",
            "Description orders the model how to use a different tool",
        )
    elif mandated_call:
        add(
            "mandated-tool-call",
            "warning",
            "Description requires the model to call another tool",
        )
    if tamper and not hijack:
        add(
            "argument-tampering",
            "warning",
            "Description forces a parameter to a fixed value",
        )
    if (_PRESSURE.search(text) or threat) and (hijack or tamper or mandated_call):
        add(
            "mandatory-pressure", "warning", "Description pressures the model to comply"
        )
    return signals
