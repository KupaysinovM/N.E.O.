"""
Natural language → structured intent.

THE BRIDGE PHASE 5 WAS MISSING
    Phase 5 accepts a structured goal, a named recipe, or a bounded proposer.
    "Open Notepad and write my homework notes" is none of those. Something has
    to read the sentence and say what kind of thing the user is asking for,
    with the slots filled in — before anything can be planned.

WHAT THIS MODULE DOES, AND WHAT IT REFUSES TO DO
    It extracts: what *kind* of request this is, and which slots the sentence
    actually contains — an application name, a piece of text to type, a window
    to close, an arithmetic expression. That is a fixed vocabulary and a fixed
    grammar of cues, written down here, and it runs with no model and no
    network.

    It refuses to: invent a slot that was not in the sentence, guess which of
    six things the user meant when the sentence supports more than one reading,
    or decide what to do. Those are the planner's job, and the planner's output
    is validated against the real registries.

THE HONEST PART — CONFIDENCE AND RESIDUE
    An `Intent` carries `confidence` and, more importantly, `unmatched`: the
    words this extractor could not place. When that is non-empty the caller
    knows the parse is partial, and the bounded model planner is asked to fill
    in the gap from the *original sentence*, not from this module's guess. When
    it is empty, the intent is complete and the model is not needed at all —
    which is the common case for "open Notepad" and the reason this module
    exists at all.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

#: Request kinds. A closed vocabulary, because every downstream consumer
#: switches on it and an open one is how an assistant grows a hundred
#: half-implemented intentions.
OPEN_APP = "open_app"
WRITE_TEXT = "write_text"
FOCUS_WINDOW = "focus_window"
CLOSE_WINDOW = "close_window"
CALCULATE = "calculate"
SEARCH_WEB = "search_web"
REMIND = "remind"
DESCRIBE_SCREEN = "describe_screen"
UNKNOWN = "unknown"

KINDS = (OPEN_APP, WRITE_TEXT, FOCUS_WINDOW, CLOSE_WINDOW, CALCULATE,
         SEARCH_WEB, REMIND, DESCRIBE_SCREEN, UNKNOWN)

#: Ceiling on the sentence this will read. A goal is a sentence; a pasted
#: document is not, and truncating is better than trying to plan against one.
MAX_TEXT_CHARS = 1200

#: The application vocabulary this extractor knows by name. It reuses
#: `core/windows/apps.py`'s aliases rather than keeping a second list, so
#: "calc" works here for the same reason it works when launched.
def _application_names() -> set:
    try:
        from core.windows import apps

        names = set(apps.ALIASES.keys())
        names.update(apps.WINDOW_TITLES.keys())
        return {str(n).lower() for n in names}
    except Exception:
        return {"notepad", "calculator", "calc", "paint", "explorer",
                "task manager", "taskmgr", "settings", "firefox", "chrome",
                "edge", "word", "excel", "powerpoint", "terminal", "cmd"}


#: Cue phrases per kind, longest first so "open and type" is not read as
#: "open" before "type" gets a look. Matching is on whole words.
_CUES = {
    OPEN_APP: ("open", "launch", "start", "run", "bring up", "show me"),
    WRITE_TEXT: ("write", "type", "enter", "put", "paste", "note down",
                 "jot down"),
    FOCUS_WINDOW: ("focus", "bring to front", "switch to", "activate",
                   "bring up the front"),
    CLOSE_WINDOW: ("close", "quit", "exit", "shut down", "kill"),
    CALCULATE: ("calculate", "compute", "work out", "what is", "sum of",
                "multiply", "divide"),
    SEARCH_WEB: ("search for", "google", "look up", "find out about",
                 "search the web"),
    REMIND: ("remind me", "reminder", "remind you", "nudge me"),
    DESCRIBE_SCREEN: ("what is on screen", "what's on my screen",
                      "describe the screen", "look at my screen", "screenshot"),
}

#: Words that carry no intent on their own. Removing them is what lets the
#: residue be meaningful: what is left over is the part this module could not
#: explain, not just the function words.
_STOPWORDS = frozenset("""
a an the and or but then so now please could would should will just
to of for in on at with into from by is are am was were be been being
do does did doing have has had having it its that this these those
my me i we you he she they them his her their our your
""".split())

_QUOTES = ("\"", "'", "“", "”", "‘", "’", "`")
_ARTICLE = re.compile(r"^(?:please\s+)?(?:can you\s+|could you\s+|would you\s+)?"
                      r"(?:just\s+)?", re.IGNORECASE)
_TRAILING = re.compile(r"[.!?]+\s*$")


@dataclass
class Intent:
    """What the sentence asks for, as far as it can honestly be read."""

    kind: str = UNKNOWN
    text: str = ""
    confidence: float = 0.0
    #: Words this extractor could not place. Non-empty means the parse is
    #: partial and the model planner is warranted.
    unmatched: list = field(default_factory=list)
    #: More than one kind is plausible — the caller must disambiguate or ask.
    alternatives: list = field(default_factory=list)
    #: Every slot found, so a planner sees the raw material rather than one
    #: interpretation of it.
    slots: dict = field(default_factory=dict)
    expression: str = ""
    source: str = ""

    @property
    def complete(self) -> bool:
        """Can this intent be planned without asking a model anything?"""
        return self.kind != UNKNOWN and not self.unmatched and not self.alternatives

    def to_dict(self) -> dict:
        return {"kind": self.kind, "text": self.text, "confidence": self.confidence,
                "unmatched": list(self.unmatched), "alternatives": list(self.alternatives),
                "slots": dict(self.slots), "expression": self.expression,
                "complete": self.complete, "source": self.source}

    def describe(self) -> str:
        bits = [f"intent={self.kind}", f"confidence={self.confidence:.2f}"]
        if self.slots:
            bits.append("slots=" + ", ".join(sorted(self.slots)))
        if self.alternatives:
            bits.append("also possible: " + ", ".join(self.alternatives))
        if self.unmatched:
            bits.append("unexplained words: " + " ".join(self.unmatched[:8]))
        return " | ".join(bits)


# ── slot extraction ─────────────────────────────────────────────────────────

def _clean(text: str) -> str:
    return _TRAILING.sub("", _ARTICLE.sub("", str(text or "").strip()))


def quoted_text(sentence: str) -> str:
    """Text the user put in quotes, if any. Quotes are an explicit instruction."""
    for opener, closer in (("\"", "\""), ("“", "”"), ("'", "'"), ("`", "`"),
                           ("‘", "’")):
        if sentence.count(opener) >= 1:
            start = sentence.find(opener)
            end = sentence.find(closer, start + 1)
            if end > start:
                return sentence[start + 1:end].strip()
    return ""


def after_keyword(sentence: str, keywords) -> str:
    """The words following the first keyword, minus the trailing clause.

    Deliberately simple and deliberately lossy: this is a hint for the planner,
    not a parse. Anything it gets wrong shows up as `unmatched` or a low
    confidence rather than as a confidently wrong slot.
    """
    lowered = sentence.lower()
    best = -1
    for keyword in keywords:
        found = lowered.find(keyword)
        if found >= 0 and (best < 0 or found < best):
            best = found + len(keyword)
    if best < 0:
        return ""
    tail = sentence[best:].strip()
    # Cut at the next cue so "open Notepad and write the text" does not make
    # the application's name part of the text to type.
    lowered_tail = tail.lower()
    stop = len(tail)
    for cues in _CUES.values():
        for cue in cues:
            found = lowered_tail.find(" " + cue)
            if found > 0:
                stop = min(stop, found)
    for conjunction in (" and then ", " but ", " after that ", ", then "):
        found = lowered_tail.find(conjunction)
        if found > 0:
            stop = min(stop, found)
    # A search cue is normally followed by a preposition — "search for X",
    # "look up X" — and the preposition is not part of the query.
    for lead in ("for ", "up ", "about ", "on "):
        if lowered_tail.startswith(lead):
            tail = tail[len(lead):]
            break
    return _clean(tail[:stop])


def application_in(sentence: str) -> str:
    """An application named in the sentence, by its own vocabulary."""
    lowered = sentence.lower()
    names = _application_names()
    best = ""
    for name in sorted(names, key=len, reverse=True):
        pattern = r"(?<![\w])" + re.escape(name) + r"(?![\w])"
        if re.search(pattern, lowered):
            if len(name) > len(best):
                best = name
    return best


def expression_in(sentence: str) -> str:
    """A bare arithmetic expression, if the sentence contains one."""
    match = re.search(r"(\d[\d\s]*(?:[+\-*/x×÷][\d\s()]+)+)", sentence)
    return re.sub(r"\s+", "", match.group(1)).replace("×", "*").replace("x", "*") \
        .replace("÷", "/") if match else ""


def _words(sentence: str) -> list:
    return [w for w in re.split(r"[^\w']+", sentence) if w]


def _residue(sentence: str, consumed: list) -> list:
    """The words nothing explained. The signal that the parse is partial."""
    explained = set()
    for phrase in consumed:
        for word in _words(phrase):
            explained.add(word.lower())
    left = [w for w in _words(sentence)
            if w.lower() not in explained and w.lower() not in _STOPWORDS]
    return left[:12]


def _cue_kinds(sentence: str) -> list:
    """Which kinds this sentence's cue words support, strongest first."""
    lowered = sentence.lower()
    found = []
    for kind, cues in _CUES.items():
        best = -1
        for cue in cues:
            at = lowered.find(cue)
            if at >= 0 and (best < 0 or at < best):
                best = at
        if best >= 0:
            found.append((best, kind))
    found.sort()
    return [kind for _at, kind in found]


# ── the extractor ───────────────────────────────────────────────────────────

def extract(sentence: str) -> Intent:
    """Read a sentence into an `Intent`. Never raises, never calls a model.

    The confidence number is deliberately blunt: it says how much of the
    sentence the cue words accounted for, not how likely the reading is to be
    what the user meant. A caller that needs the second thing has to ask a
    person.
    """
    raw = str(sentence or "").strip()[:MAX_TEXT_CHARS]
    intent = Intent(text=raw, source="intent.extract")
    if not raw:
        return intent

    sentence = _clean(raw)
    lowered = sentence.lower()

    # Slots first: they are facts, and facts do not depend on which reading of
    # the sentence wins.
    app = application_in(sentence)
    quoted = quoted_text(raw)
    expression = expression_in(sentence)
    if app:
        intent.slots["app_name"] = app
    if quoted:
        intent.slots["text"] = quoted
    if expression:
        intent.slots["expression"] = expression
    trailing = after_keyword(sentence, _CUES[SEARCH_WEB])
    if trailing and trailing not in intent.slots.get("text", ""):
        intent.slots.setdefault("query", trailing)

    consumed = [c for c in [app, quoted, expression] if c]
    kinds = _cue_kinds(sentence)
    # The cue words are *explained* by the reading, so they are not residue.
    # Only words nothing accounted for end up in `unmatched`.
    consumed.extend(cue for kind in kinds[:1] for cue in _CUES.get(kind, ()))

    if not kinds:
        intent.kind = UNKNOWN
        intent.unmatched = _residue(sentence, consumed)
        intent.confidence = 0.0
        return intent

    intent.kind = kinds[0]
    intent.alternatives = kinds[1:3]
    # One override, written down rather than emergent: an arithmetic expression
    # in the sentence is strong evidence that this is a calculation, even when
    # an earlier word ("open") would otherwise win on position. "Open calculator
    # and calculate 123*456" is one request, and reading it as "open calculator"
    # and dropping the rest is how half a request gets executed.
    if expression and CALCULATE in kinds and intent.kind != CALCULATE:
        intent.alternatives = [intent.kind] + intent.alternatives[:1]
        intent.kind = CALCULATE
    intent.unmatched = _residue(sentence, consumed)

    # Confidence: how much of the sentence the cues and the slots explain. A
    # long sentence with one cue word in it is a low-confidence reading, and
    # the planner is told so rather than handed a guess dressed as a fact.
    explained = len(_words(" ".join(str(c) for c in consumed)))
    total = max(1, len(_words(sentence)))
    intent.confidence = round(min(1.0, (explained + 2) / (total + 2)), 2)
    if intent.alternatives:
        intent.confidence = round(intent.confidence * 0.7, 2)
    return intent


def summary(intent: Intent) -> str:
    """One bounded line for a prompt, a log, or a task record."""
    if intent.kind == UNKNOWN:
        return ("NEO could not tell what this request is about: "
                + (", ".join(intent.unmatched[:8]) or "no usable cue words"))
    parts = [f"request: {intent.kind}"]
    if "app_name" in intent.slots:
        parts.append(f"application: {intent.slots['app_name']}")
    if "text" in intent.slots:
        parts.append(f"text: {intent.slots['text'][:120]!r}")
    if intent.alternatives:
        parts.append("also possible: " + ", ".join(intent.alternatives))
    if intent.unmatched:
        parts.append("unexplained: " + " ".join(intent.unmatched[:6]))
    return "; ".join(parts)