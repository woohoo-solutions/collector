"""Configuration inheritance: IOS-XR `group` / `apply-group` and Junos `groups` / `apply-groups`.

Both platforms let a configuration say something once and apply it in many
places. A reader that reads the text as written misses every statement that
lives only in a group: on Junos the routing engine's `host-name`, on IOS-XR
the `load-interval` of every bundle. This module resolves the inheritance
before the readers run, so they read the configuration the device runs.

The resolved configuration is still text, one line at a time, and each line
carries the line number it was written on: an inherited line carries the
group's own line, so a reader that reads it registers the group's line in
the statement ledger (`netstate.ledger`), and its ancestry carries the line
of the object it was inherited into. One group line applied to forty
interfaces is one statement, counted once.

Junos `apply-groups-except` is resolved as the Junos documentation states
it ("Disable inheritance of a configuration group", allowed at every
hierarchy level but the top): the groups it names give nothing at that
level or anywhere below it, while every other group still applies there,
and the same groups still apply everywhere else. Where the documentation
does not say what the device does, the resolver does not guess: it applies
the group nowhere it might be excepted and lists the construct in
`ResolvedConfig.unresolved`. Those cases are an `apply-groups-except` at
the top level, a group both applied and excepted at one level, a group
applied again below an `apply-groups-except` that names it, and an
`apply-groups-except` inside a group's own content.

What the resolver does not do: it does not change what a statement says,
it does not read `set` (display set) configurations, it does not evaluate a
Junos group's `when` condition (such a group is applied as if always true),
and it does not invent a group it was not shown. A group whose content is
not interface blocks (IOS-XR), an `apply-group` inside a stanza (IOS-XR),
a nested group application (`apply-groups` inside a group), an apply line
naming a group that is not defined, and a Junos engine group named with its
pair (`re0` and `re1`) are not resolved and are listed in
`ResolvedConfig.unresolved`. An IOS-XR apply line the resolver does not
resolve stays in the effective configuration as written; a Junos
`apply-groups` or `apply-groups-except` line never does, whether or not
every group it names was resolved. A group's content the resolver cannot
apply stays in that group's definition and applies nowhere.

The model keeps what a configuration generator needs to render the groups
back rather than the expansion: each group's own lines as written, where it
was applied, and every place where an explicit statement overrode what a
group would have given. This module must not import anything from DiscoNet.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import functools
import re
from dataclasses import dataclass
from netstate.ledger import ConfigLine, consume
from netstate.platforms import IOSXR, JUNOS

EXPLICIT = "explicit"

# Junos group names that apply only on one routing engine, one cluster node
# or one virtual-chassis member. Which one answered cannot be told from the
# configuration, so the resolver applies such a group only where it is the
# one of its kind applied: `apply-groups [ re0 re1 ]` names one name per
# engine, and choosing either would be a guess (BUG-291).
_ENGINE_GROUP = re.compile(r"^(?:re[01]|node[01]|member\d+)$")

# Leaves that hold one value, so that a group's value and an explicit value
# are two settings of one knob, not two entries of a list. Junos has no
# grammar in this tool, so this is a list of what is known to be single, and
# anything else is merged as a list (an `address`, a `member`, a `server`),
# with the explicit statement first.
_JUNOS_SINGLE = frozenset({
    "host-name", "domain-name", "time-zone", "description", "mtu", "router-id",
    "autonomous-system", "backup-router", "location", "contact", "vlan-id",
    "encapsulation", "speed", "native-vlan-id",
})

# IOS-XR interface statements whose first word is a family, not the knob:
# `ipv4 address` and `ipv4 mtu` are two knobs, `service-policy input` and
# `service-policy output` two more.
_XR_TWO_WORD = frozenset({
    "ipv4", "ipv6", "service-policy", "bfd", "mpls", "lldp", "cdp", "bundle", "no",
    "encapsulation", "flow", "dampening",
})

_JUNOS_ANNOTATION = re.compile(r"\s*##.*$")
_JUNOS_WORD = re.compile(r'"[^"]*"|\S+')
_XR_GROUP = re.compile(r"^group\s+(?P<name>\S+)\s*$")
_XR_APPLY = re.compile(r"^apply-group\s+(?P<names>\S.*?)\s*$")
_XR_PATTERN = re.compile(r"""^interface\s+(?P<quote>['"]?)(?P<regex>.+?)(?P=quote)\s*$""")
_XR_INTERFACE = re.compile(r"^interface\s+(?P<name>\S+)\s*$")


@dataclass(frozen=True)
class ResolvedLine:
    """One line of the configuration a device runs, as text, with where it was written.

    `line_no` is the line of the configuration text the statement was
    written on: the explicit statement's own line, or for an inherited one
    the group's line. `origin` is `explicit` or `group:<name>`.
    """

    line_no: int
    text: str
    origin: str = EXPLICIT


@dataclass(frozen=True)
class GroupDefinition:
    """A group as written, for a generator to render back: its name and its own lines."""

    name: str
    line_no: int
    lines: tuple[ResolvedLine, ...]


@dataclass(frozen=True)
class Application:
    """Where a configuration applies groups: the line, the groups in priority order, the context."""

    line_no: int
    groups: tuple[str, ...]
    context: tuple[str, ...] = ()


@dataclass(frozen=True)
class Override:
    """A knob an explicit statement and a group both set; the explicit statement wins."""

    context: tuple[str, ...]
    group: str
    group_line: int
    group_text: str
    explicit_line: int
    explicit_text: str


@dataclass(frozen=True)
class Unresolved:
    """A group construct the resolver saw and did not resolve, with why."""

    line_no: int
    text: str
    reason: str


@dataclass(frozen=True)
class ResolvedConfig:
    """The configuration a device runs once its groups are applied.

    `lines` is the effective configuration in the device's own syntax, the
    group definitions and the lines that apply them left out (they are
    structure, kept in `groups` and `applications`). `groups_applied` names
    the groups that gave something, in the order first applied.
    """

    device: str
    os_name: str
    lines: tuple[ResolvedLine, ...]
    groups_applied: tuple[str, ...] = ()
    groups: tuple[GroupDefinition, ...] = ()
    applications: tuple[Application, ...] = ()
    overridden_by_explicit: tuple[Override, ...] = ()
    unresolved: tuple[Unresolved, ...] = ()
    # Junos `apply-groups-except`: where a level takes groups away, the
    # names as written. Kept beside `applications` for a generator to render.
    exceptions: tuple[Application, ...] = ()
    # The lines the resolver itself read the meaning of: the group headers,
    # the IOS-XR interface patterns and the apply lines. A group's statements
    # are not among them: they are credited by the reader that reads the
    # inherited copy, as any other statement is.
    structure: tuple[int, ...] = ()

    @property
    def inherits(self) -> bool:
        """Whether any line of the effective configuration came from a group."""
        return bool(self.groups_applied)

    def config_lines(self) -> list[ConfigLine]:
        """The effective configuration as `ConfigLine`s, each carrying its written line number."""
        return [ConfigLine(line.text, line.line_no) for line in self.lines]

    def text(self) -> str:
        """The effective configuration as one text. Line numbers are lost: for display only."""
        return "\n".join(line.text for line in self.lines) + ("\n" if self.lines else "")

    def origins(self) -> dict[int, str]:
        """`line number -> origin` for every inherited line."""
        return {line.line_no: line.origin for line in self.lines if line.origin != EXPLICIT}


def _plain(config: str, os_name: str, device: str) -> ResolvedConfig:
    return ResolvedConfig(
        device=device, os_name=os_name,
        lines=tuple(ResolvedLine(n, text) for n, text in enumerate(config.splitlines(), 1)),
    )


# --------------------------------------------------------------------------
# IOS-XR
# --------------------------------------------------------------------------


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip())


def _xr_knob(text: str) -> str:
    """The knob an IOS-XR interface statement sets: its first word, or two for a family."""
    words = text.split()
    if not words:
        return ""
    if words[0].lower() in _XR_TWO_WORD and len(words) > 1:
        return f"{words[0].lower()} {words[1].lower()}"
    return words[0].lower()


@dataclass
class _XrPattern:
    line_no: int
    regex: "re.Pattern[str]"
    # Each item is one statement under the pattern with the lines under it.
    items: list[list[tuple[int, str]]]


def _xr_items(body: list[tuple[int, str]]) -> list[list[tuple[int, str]]]:
    """The statements directly under a block, each with the lines under it; `!` lines dropped."""
    lines = [(n, t) for n, t in body if t.strip() and not t.strip().startswith("!")]
    if not lines:
        return []
    depth = min(_indent(t) for _, t in lines)
    items: list[list[tuple[int, str]]] = []
    for number, text in lines:
        if _indent(text) == depth or not items:
            items.append([(number, text)])
        else:
            items[-1].append((number, text))
    return items


def resolve_iosxr(config: str, device: str = "") -> ResolvedConfig:
    """IOS-XR `group` / `end-group` blocks applied by a top-level `apply-group`.

    Inside a group, `interface '<regex>'` blocks apply their statements to
    every configured interface whose name, as configured, the regex matches
    whole (`re.fullmatch`). A statement the interface states itself wins,
    and the conflict is recorded. Groups apply in the order the
    `apply-group` lines name them; the first to set a knob keeps it.
    Inherited statements follow the interface's own, indented as its own.
    """
    if not re.search(r"^(?:group|apply-group)\s", config, re.MULTILINE):
        return _plain(config, IOSXR.key, device)
    raw = config.splitlines()
    patterns: dict[str, list[_XrPattern]] = {}
    groups: list[GroupDefinition] = []
    applications: list[Application] = []
    unresolved: list[Unresolved] = []
    structure: list[int] = []
    kept: list[tuple[int, str]] = []
    index = 0
    while index < len(raw):
        number, text = index + 1, raw[index]
        index += 1
        group = _XR_GROUP.match(text)
        if group:
            end = next((i for i in range(index, len(raw)) if raw[i].strip() == "end-group" and not _indent(raw[i])), None)
            if end is None:
                # No `end-group`: not a group this resolver can bound; read as written.
                unresolved.append(Unresolved(number, text, "group without end-group"))
                kept.append((number, text))
                continue
            name = group.group("name")
            body = [(n, raw[n - 1]) for n in range(index + 1, end + 1)]
            groups.append(GroupDefinition(name, number, tuple(ResolvedLine(n, t) for n, t in [(number, text), *body, (end + 1, raw[end])])))
            structure.extend((number, end + 1))
            found = patterns.setdefault(name, [])
            for item in _xr_items(body):
                head_no, head = item[0]
                pattern = _XR_PATTERN.match(head.strip())
                if pattern is None:
                    unresolved.append(Unresolved(head_no, head.strip(), "group content other than interface blocks"))
                    continue
                try:
                    regex = re.compile(pattern.group("regex"))
                except re.error:
                    unresolved.append(Unresolved(head_no, head.strip(), "a regex Python cannot read"))
                    continue
                structure.append(head_no)
                found.append(_XrPattern(head_no, regex, _xr_items(item[1:])))
            index = end + 1
            continue
        apply = _XR_APPLY.match(text)
        if apply:
            applications.append(Application(number, tuple(apply.group("names").split())))
            structure.append(number)
            continue
        if text.strip().startswith("apply-group ") and _indent(text):
            unresolved.append(Unresolved(number, text.strip(), "apply-group inside a stanza"))
        kept.append((number, text))

    applied = [name for application in applications for name in application.groups]
    for application in applications:
        for name in application.groups:
            if name not in patterns:
                unresolved.append(Unresolved(application.line_no, f"apply-group {name}", "no such group"))

    lines: list[ResolvedLine] = []
    overrides: list[Override] = []
    used: list[str] = []

    def inherit(name_line: tuple[int, str], body: list[tuple[int, str]]) -> None:
        interface = _XR_INTERFACE.match(name_line[1])
        if not interface or not applied:
            return
        name = interface.group("name")
        own = {_xr_knob(item[0][1]): item[0] for item in _xr_items(body)}
        given: set[str] = set()
        for group in applied:
            for pattern in patterns.get(group, ()):
                if not pattern.regex.fullmatch(name):
                    continue
                for item in pattern.items:
                    knob = _xr_knob(item[0][1])
                    if knob in own:
                        # The same statement stated twice is no conflict.
                        if own[knob][1].strip() == item[0][1].strip():
                            continue
                        overrides.append(Override(
                            (name_line[1].strip(),), group, item[0][0], item[0][1].strip(),
                            own[knob][0], own[knob][1].strip()))
                        continue
                    if knob in given:
                        continue
                    given.add(knob)
                    shift = _indent(item[0][1]) - 1
                    for number, text in item:
                        lines.append(ResolvedLine(number, " " * max(_indent(text) - shift, 1) + text.strip(), f"group:{group}"))
                    if group not in used:
                        used.append(group)

    # Walk the kept lines stanza by stanza; an interface stanza's inherited
    # lines go after its own, before the `!` or the next stanza.
    stanza: list[tuple[int, str]] = []

    def flush() -> None:
        if stanza:
            lines.extend(ResolvedLine(n, t) for n, t in stanza)
            inherit(stanza[0], stanza[1:])
            stanza.clear()

    for number, text in kept:
        if text.strip() and not _indent(text):
            flush()
            if text.strip() == "!":
                lines.append(ResolvedLine(number, text))
            else:
                stanza.append((number, text))
        elif stanza:
            stanza.append((number, text))
        else:
            lines.append(ResolvedLine(number, text))
    flush()
    return ResolvedConfig(
        device=device, os_name=IOSXR.key, lines=tuple(lines), groups_applied=tuple(used),
        groups=tuple(groups), applications=tuple(applications),
        overridden_by_explicit=tuple(overrides), unresolved=tuple(unresolved),
        structure=tuple(sorted(set(structure))),
    )


# --------------------------------------------------------------------------
# Junos
# --------------------------------------------------------------------------


@dataclass
class _Node:
    text: str
    line_no: int
    children: list["_Node"] | None  # None for a leaf
    origin: str = EXPLICIT
    inactive: bool = False

    @property
    def key(self) -> str:
        return " ".join(_JUNOS_WORD.findall(self.text))


def _junos_tree(config: str) -> list[_Node]:
    """The braces as a tree; `inactive:` marked, `protect:` dropped, annotations stripped."""
    root: list[_Node] = []
    stack: list[list[_Node]] = [root]
    for number, raw in enumerate(config.splitlines(), 1):
        line = _JUNOS_ANNOTATION.sub("", raw.strip())
        if not line or line.startswith(("#", "/*", "*")):
            continue
        if line == "}":
            if len(stack) > 1:
                stack.pop()
            continue
        opens = line.endswith("{")
        text = line[:-1].strip() if opens else line.rstrip(";").strip()
        inactive = False
        while text.startswith(("inactive:", "protect:")):
            inactive = inactive or text.startswith("inactive:")
            text = text.split(":", 1)[1].strip()
        node = _Node(text, number, [] if opens else None, inactive=inactive)
        stack[-1].append(node)
        if opens:
            stack.append(node.children)  # type: ignore[arg-type]
    return root


def _apply_names(node: _Node, keyword: str = "apply-groups") -> list[str] | None:
    """The group names an `apply-groups` leaf lists (or `apply-groups-except`, by `keyword`)."""
    words = _JUNOS_WORD.findall(node.text)
    if node.children is not None or not words or words[0] != keyword:
        return None
    return [w.strip('"') for w in words[1:] if w not in ("[", "]")]


def _except_names(node: _Node) -> list[str] | None:
    return _apply_names(node, "apply-groups-except")


def _structural(node: _Node) -> bool:
    """An `apply-groups` or `apply-groups-except` leaf: structure, not a statement the device runs."""
    return _apply_names(node) is not None or _except_names(node) is not None


def _is_pattern(word: str) -> bool:
    """A `<wildcard>` word, quoted or not: Junos prints `"<*>"` as often as `<*>`."""
    word = word.strip('"')
    return len(word) > 1 and word.startswith("<") and word.endswith(">")


def _matches(group_key: str, key: str) -> bool:
    """Whether a group's statement names this one: equal, or by `<wildcard>` word for word."""
    if group_key == key:
        return True
    ours, theirs = _JUNOS_WORD.findall(group_key), _JUNOS_WORD.findall(key)
    if len(ours) != len(theirs) or not any(_is_pattern(w) for w in ours):
        return False
    return all(
        a == b or (_is_pattern(a) and fnmatch.fnmatchcase(b.strip('"'), a.strip('"')[1:-1]))
        for a, b in zip(ours, theirs)
    )


def _wildcard(node: _Node) -> bool:
    return any(_is_pattern(w) for w in _JUNOS_WORD.findall(node.key))


_Context = tuple[str, list[_Node]]  # (group name, the group's nodes at this level)


class _JunosResolver:
    def __init__(self, groups: dict[str, _Node]):
        self.groups = groups
        self.overrides: list[Override] = []
        self.applications: list[Application] = []
        self.exceptions: list[Application] = []
        self.unresolved: list[Unresolved] = []
        self.structure: list[int] = []
        self.used: list[str] = []

    def _navigate(self, name: str, path: tuple[str, ...]) -> list[_Node]:
        nodes = list(self.groups[name].children or [])
        for key in path:
            nodes = [c for n in nodes if n.children is not None and not n.inactive and _matches(n.key, key) for c in n.children]
        return nodes

    def _excepted_here(self, children: list[_Node], path: tuple[str, ...]) -> set[str]:
        """The groups an `apply-groups-except` at this level names: not inherited here or below.

        Junos accepts the statement at every level but the top; one at the top
        is reported and has no effect, since no device runs such a
        configuration and what it would mean is not documented.
        """
        found: set[str] = set()
        for child in children:
            names = _except_names(child)
            if names is None:
                continue
            self.structure.append(child.line_no)
            self.exceptions.append(Application(child.line_no, tuple(names), path))
            if not path:
                self.unresolved.append(Unresolved(
                    child.line_no, child.text, "apply-groups-except at the top level, which Junos does not accept"))
                continue
            for name in names:
                if name not in self.groups:
                    self.unresolved.append(Unresolved(child.line_no, child.text, f"no such group {name}"))
            found.update(names)
        return found

    def _applied_here(self, children: list[_Node], path: tuple[str, ...],
                      excepted_here: set[str] | frozenset[str] = frozenset(), excepted_above: frozenset[str] = frozenset()) -> list[_Context]:
        found: list[_Context] = []
        for child in children:
            names = _apply_names(child)
            if names is None:
                continue
            self.structure.append(child.line_no)
            engines = [n for n in names if _ENGINE_GROUP.match(n) and n in self.groups]
            usable: list[str] = []
            for name in names:
                if name not in self.groups:
                    self.unresolved.append(Unresolved(child.line_no, child.text, f"no such group {name}"))
                elif name in excepted_here:
                    # Applied and excepted at one level: the documentation does
                    # not say which wins, so neither is guessed and the group
                    # gives nothing here.
                    self.unresolved.append(Unresolved(
                        child.line_no, child.text,
                        f"{name} is applied and excepted at the same level; not applied"))
                elif name in excepted_above:
                    # Applied again below an `apply-groups-except` that names
                    # it: whether that re-enables the group is not documented.
                    self.unresolved.append(Unresolved(
                        child.line_no, child.text,
                        f"{name} is applied below an apply-groups-except that names it; not applied"))
                elif name in engines and len(engines) > 1:
                    self.unresolved.append(Unresolved(
                        child.line_no, child.text,
                        f"{name} applies on one routing engine of {', '.join(engines)}; which answered is not known"))
                else:
                    usable.append(name)
            self.applications.append(Application(child.line_no, tuple(names), path))
            found.extend((name, self._navigate(name, path)) for name in usable)
        return found

    @staticmethod
    def _descend(contexts: list[_Context], key: str) -> list[_Context]:
        return [
            (name, [c for n in nodes if n.children is not None and not n.inactive and _matches(n.key, key) for c in n.children])
            for name, nodes in contexts
        ]

    def merge(self, explicit: list[_Node], inherited: list[_Context], path: tuple[str, ...],
              excepted: frozenset[str] = frozenset()) -> list[_Node]:
        """One level: the explicit statements first, then what each group gives, in priority order.

        `excepted` is the groups an `apply-groups-except` above has taken
        away: they give nothing at this level or below.
        """
        explicit = [n for n in explicit if not n.inactive]
        here = self._excepted_here(explicit, path)
        contexts = self._applied_here(explicit, path, here, excepted) + inherited
        excepted = excepted | here
        contexts = [(name, nodes) for name, nodes in contexts if name not in excepted]
        result: list[_Node] = []
        keys: dict[str, _Node] = {}
        for node in explicit:
            if _structural(node) or (not path and node.key == "groups"):
                continue
            below = self._descend(contexts, node.key)
            has_group_children = any(nodes for _, nodes in below)
            if node.children is None and not has_group_children:
                merged = node
            else:
                merged = _Node(node.text, node.line_no,
                               self.merge(node.children or [], below, (*path, node.key), excepted), node.origin)
            result.append(merged)
            keys[node.key] = merged
        for name, nodes in contexts:
            for node in nodes:
                if node.inactive or _wildcard(node) or node.key in keys or _structural(node):
                    if _apply_names(node) is not None:
                        self.unresolved.append(Unresolved(node.line_no, node.text, "apply-groups inside a group"))
                    elif _except_names(node) is not None:
                        self.unresolved.append(Unresolved(node.line_no, node.text, "apply-groups-except inside a group"))
                    continue
                if node.children is None:
                    word = node.key.split()[0] if node.key else ""
                    rival = next((r for r in result if r.children is None and word in _JUNOS_SINGLE
                                  and r.key.split()[:1] == [word]), None)
                    if rival is not None:
                        if rival.origin == EXPLICIT and rival.key != node.key:
                            self.overrides.append(Override(path, name, node.line_no, node.text, rival.line_no, rival.text))
                        continue
                    made = _Node(node.text, node.line_no, None, f"group:{name}")
                else:
                    below = self._descend(contexts, node.key)
                    made = _Node(node.text, node.line_no, self.merge([], below, (*path, node.key), excepted), f"group:{name}")
                result.append(made)
                keys[node.key] = made
                if name not in self.used:
                    self.used.append(name)
        return result


def _emit(nodes: list[_Node], depth: int, out: list[ResolvedLine]) -> None:
    pad = "    " * depth
    for node in nodes:
        if node.children is None:
            out.append(ResolvedLine(node.line_no, f"{pad}{node.text};", node.origin))
            continue
        out.append(ResolvedLine(node.line_no, f"{pad}{node.text} {{", node.origin))
        _emit(node.children, depth + 1, out)
        out.append(ResolvedLine(0, f"{pad}}}", node.origin))


def _group_lines(node: _Node) -> tuple[ResolvedLine, ...]:
    out: list[ResolvedLine] = []
    _emit([node], 0, out)
    return tuple(out)


def resolve_junos(config: str, device: str = "") -> ResolvedConfig:
    """Junos `groups` applied by `apply-groups` at any level.

    A group's statements at the path where it is applied merge into the
    configuration there: a container the configuration has gains what the
    group puts under it, a container it lacks is created, and a `<pattern>`
    in a group's statement applies to every statement of the configuration
    it matches (and creates none). The explicit configuration has priority,
    then the groups applied at the most specific level, then each `apply-groups`
    list in its own order. An `apply-groups-except` at a level takes the
    groups it names away from that level and every level below it; the
    cases the documentation leaves open are listed in `unresolved` and the
    group is not applied there. An `inactive:` statement is not configuration
    the device runs, in a group or out of one; `protect:` only locks a
    statement and is dropped from its text.
    """
    if not re.search(r"^\s*apply-groups(?:-except)?\s", config, re.MULTILINE):
        return _plain(config, JUNOS.key, device)
    tree = _junos_tree(config)
    groups: dict[str, _Node] = {}
    for node in tree:
        if node.key == "groups" and node.children is not None:
            for group in node.children:
                if group.children is not None and not group.inactive:
                    groups[group.key.strip('"')] = group
    resolver = _JunosResolver(groups)
    effective = resolver.merge(tree, [], ())
    lines: list[ResolvedLine] = []
    _emit(effective, 0, lines)
    return ResolvedConfig(
        device=device, os_name=JUNOS.key, lines=tuple(lines), groups_applied=tuple(resolver.used),
        groups=tuple(GroupDefinition(name, node.line_no, _group_lines(node)) for name, node in groups.items()),
        applications=tuple(resolver.applications), exceptions=tuple(resolver.exceptions),
        overridden_by_explicit=tuple(resolver.overrides), unresolved=tuple(dict.fromkeys(resolver.unresolved)),
        structure=tuple(sorted(set(resolver.structure))),
    )


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------


@functools.lru_cache(maxsize=16)
def _resolve_cached(config: str, nested: bool) -> ResolvedConfig:
    return resolve_junos(config) if nested else resolve_iosxr(config)


def resolve(config: str, nested: bool, device: str = "") -> ResolvedConfig:
    """The effective configuration of one device, its groups applied.

    `nested` is the platform's `config_nested`: braces (Junos) or indentation.
    On an indented configuration only IOS-XR has groups; any other platform's
    text has no `group` / `apply-group` at the top level and comes back as
    written. The resolver registers the lines it read itself (group headers,
    patterns, apply lines) in the ledger; the device name is only a label.
    """
    resolved = _resolve_cached(config or "", bool(nested))
    consume(None, resolved.structure, "inheritance.resolve")
    return dataclasses.replace(resolved, device=device) if device else resolved


def effective_lines(config: str, nested: bool) -> list[ConfigLine]:
    """The effective configuration as numbered lines: what the line walkers read."""
    return resolve(config, nested).config_lines()

