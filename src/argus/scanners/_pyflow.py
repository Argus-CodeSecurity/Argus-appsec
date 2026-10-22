"""Flow-sensitive taint and constant analysis over a tree-sitter Python tree.

This is the engine behind the ``ast-python`` scanner (and the depth-1
cross-file tier that reuses it). It walks one function at a time, statement by
statement, and keeps an abstract value per variable:

* ``taint``: derived from an untrusted source (``request.args``, ``input()``, ...),
  with the set of CWEs a sanitizer or a guard has already cleared it for.
* ``lit``: derived only from literals, so it can never carry attacker data.
  This is what lets the scanner say "this ``shell=True`` command is constant".
* ``const``: the exact value, when it is a small literal and every path agrees.
  Used to fold conditions such as ``if 7 * 18 + num > 200`` and prune the
  branch that can never run.
* ``weak``: derived from the non-cryptographic ``random`` module.
* a few flags (``path`` for pathlib objects, ``xxe`` for XML parsers with
  external entities enabled, ``reqobj`` for objects built from the request).
* element-wise values for literal dicts, lists and ``configparser`` objects,
  so ``d['a'] = user; x = d['b']`` does not taint ``x``.

Control flow is structured: ``if``/``elif``/``else``, ``match``, loops and
``try`` are analyzed per branch and joined, so a clean reassignment inside one
branch (``if not p: p = ""``) no longer erases the taint the other branch keeps.
A branch whose condition folds to a constant is skipped, and a block that
always returns or raises does not flow into the code after it. Simple guards
refine the state on each side of a condition: an early return when
``'../' in p`` clears ``p`` for path traversal, an allowlist membership test
clears it entirely, and a ``urlparse(u).netloc`` allowlist clears ``u`` for
open redirect.

Everything here is intra-procedural and deliberately simple. Python's own
recursion is bounded: statements and expressions nested deeper than a fixed
limit fall back to a flat, conservative scan instead of recursing further, so a
hostile file cannot exhaust the stack.
"""

from __future__ import annotations

import ast as _pyast
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from argus.context import LanguageContext

#: Sentinel for "value not known". A plain object: identity comparison only.
NOCONST: Any = object()

MAX_EXPR_DEPTH = 60
MAX_STMT_DEPTH = 60
MAX_ITEMS = 64  # container elements tracked one by one
MAX_STR = 4096  # longest folded constant string
MAX_LITERAL_TEXT = 4096  # longest literal handed to ast.literal_eval
LOOP_ROUNDS = 3
#: Statement visits per run before giving up on a (hostile) file. The scanner
#: reports such a file as skipped instead of spending unbounded time on it.
MAX_STEPS = 400_000


class AnalysisBudgetExceeded(RuntimeError):
    """A file needed more analysis work than :data:`MAX_STEPS` allows."""


CWE_SQL = "CWE-89"
CWE_CMD = "CWE-78"
CWE_PATH = "CWE-22"
CWE_CODE = "CWE-95"
CWE_DESER = "CWE-502"
CWE_XSS = "CWE-79"
CWE_REDIRECT = "CWE-601"
CWE_XXE = "CWE-611"
CWE_LDAP = "CWE-90"
CWE_XPATH = "CWE-643"
CWE_TRUST = "CWE-501"
CWE_WEAKRAND = "CWE-330"

#: Sink id -> the CWEs a sanitizer must clear for the value to be safe there.
SINK_CWES: dict[str, frozenset[str]] = {
    "ast-sql-injection": frozenset({CWE_SQL}),
    "ast-sql-string-building": frozenset({CWE_SQL}),
    "ast-command-injection": frozenset({CWE_CMD}),
    "ast-path-traversal": frozenset({CWE_PATH}),
    "ast-code-injection": frozenset({CWE_CODE}),
    "ast-unsafe-deserialization": frozenset({CWE_DESER}),
    "ast-xss": frozenset({CWE_XSS}),
    "ast-open-redirect": frozenset({CWE_REDIRECT}),
    "ast-xxe": frozenset({CWE_XXE}),
    "ast-ldap-injection": frozenset({CWE_LDAP}),
    "ast-xpath-injection": frozenset({CWE_XPATH}),
    "ast-trust-boundary": frozenset({CWE_TRUST}),
    "ast-weak-random": frozenset({CWE_WEAKRAND}),
    "ast-eval-of-parameter": frozenset({CWE_CODE}),
}
#: Sinks that do not depend on a tainted source (excluded from summaries).
NON_TAINT_SINKS = frozenset({"ast-sql-string-building", "ast-weak-random", "ast-eval-of-parameter"})
TAINT_CWES: frozenset[str] = frozenset(
    c for sid, cwes in SINK_CWES.items() if sid not in NON_TAINT_SINKS for c in cwes
) | frozenset({"CWE-80", "CWE-94"})

# Untrusted-input sources: an attribute chain or call target matching one of
# these is tainted. ``request.path`` and friends are attacker-controlled too.
SOURCE_RE = re.compile(
    r"\brequest\.(?:args|form|values|json|data|files|cookies|headers|query_params|GET|POST|"
    r"path|full_path|url|base_url|query_string|stream|get_json|get_data|referrer|environ|"
    r"body|path_params|match_info|COOKIES|FILES|META|remote_user)\b"
    r"|\binput\s*\("
    r"|\bsys\.argv\b"
    r"|\bflask\.request\b"
    r"|\bos\.environ\b"
)

# Function-name last components that neutralize taint for every sink (numeric
# coercion, quoting, path basename). Keyed on the final identifier of the target.
UNIVERSAL_SANITIZERS = frozenset(
    {
        "int",
        "float",
        "bool",
        "len",
        "ord",
        "abs",
        "round",
        "complex",
        "secure_filename",
        "basename",
        "quote",
        "safe_join",
        "quote_plus",
        "shlex",
        "url_for",
        "getint",
        "getfloat",
        "getboolean",
        "uuid4",
        "hexdigest",
    }
)
_IMMUTABLE_LITERALS = frozenset(
    {
        "string",
        "concatenated_string",
        "integer",
        "float",
        "true",
        "false",
        "none",
        "tuple",
        "binary_operator",
        "parenthesized_expression",
    }
)
_DICT_CTORS = frozenset(
    {"dict", "OrderedDict", "ConfigParser", "RawConfigParser", "SafeConfigParser"}
)
_LIST_CTORS = frozenset({"list", "deque"})
#: Sanitizers whose result is a number: it cannot carry attacker text at all.
NUMERIC_SANITIZERS = frozenset(
    {"int", "float", "bool", "len", "ord", "abs", "round", "complex", "getint", "getfloat"}
    | {"getboolean", "uuid4", "hexdigest"}
)
_XSS_CLEAN = frozenset({CWE_XSS, "CWE-80"})
_SQL_ESCAPES = frozenset({"escape", "escape_string", "escape_literal", "real_escape_string"})
_LDAP_ESCAPES = frozenset({"escape_filter_chars", "escape_dn_chars", "escape_rdn", "filter_format"})
_XSS_SANITIZER_NAMES = frozenset({"quoteattr", "strip_tags", "sanitize_html", "clean", "linkify"})

# Calls whose result is literal-derived when the receiver and arguments are.
PURE_FUNCTIONS = frozenset(
    {
        "str",
        "repr",
        "format",
        "bytes",
        "bytearray",
        "list",
        "tuple",
        "dict",
        "set",
        "frozenset",
        "sorted",
        "reversed",
        "min",
        "max",
        "sum",
        "chr",
        "hex",
        "oct",
        "bin",
        "b64encode",
        "b64decode",
        "urlsafe_b64encode",
        "urlsafe_b64decode",
        "b32encode",
        "b32decode",
        "b16encode",
        "b16decode",
        "hexlify",
        "unhexlify",
        "unquote",
        "unquote_plus",
        "urlencode",
        "unescape",
        "dumps",
        "loads",
        "join",
        "dirname",
        "splitext",
        "normpath",
        "deepcopy",
        "copy",
        "escape",
        "escape_for_html",
    }
)
PURE_METHODS = frozenset(
    {
        "encode",
        "decode",
        "format",
        "join",
        "replace",
        "strip",
        "lstrip",
        "rstrip",
        "upper",
        "lower",
        "title",
        "capitalize",
        "casefold",
        "swapcase",
        "split",
        "rsplit",
        "splitlines",
        "partition",
        "rpartition",
        "zfill",
        "center",
        "ljust",
        "rjust",
        "removeprefix",
        "removesuffix",
        "expandtabs",
        "translate",
        "find",
        "rfind",
        "index",
        "rindex",
        "count",
        "startswith",
        "endswith",
        "copy",
        "get",
        "keys",
        "values",
        "items",
    }
)
_LIT_ATTRS = frozenset(
    {
        "os.name",
        "os.sep",
        "os.linesep",
        "os.pathsep",
        "os.curdir",
        "os.pardir",
        "sys.platform",
        "sys.maxsize",
        "string.ascii_letters",
        "string.ascii_lowercase",
        "string.ascii_uppercase",
        "string.digits",
        "string.hexdigits",
        "string.punctuation",
        "string.printable",
    }
)
_MUTATORS = frozenset(
    {
        "append",
        "appendleft",
        "extend",
        "insert",
        "pop",
        "popleft",
        "remove",
        "clear",
        "set",
        "update",
        "setdefault",
        "add",
        "discard",
        "write",
        "writelines",
        "put",
        "sort",
        "reverse",
    }
)

# --- sink target patterns (matched against the compact call target) ----------
SQL_FN = re.compile(r"(?:^|\.)(?:execute|executemany|executescript)$")
CMD_FN = re.compile(
    r"(?:^|\.)system$|(?:^|\.)popen$|^subprocess\.\w+$|^os\.(?:exec\w*|spawn\w*)$"
    r"|^commands\.getoutput$|^pty\.spawn$"
)
PATH_FN = re.compile(
    r"(?:^|\.)open$|send_file$|^os\.path\.(?:exists|lexists|isfile|isdir|getsize|getmtime)$"
    r"|^os\.(?:remove|unlink|rmdir|removedirs|mkdir|makedirs|listdir|scandir|stat|lstat|"
    r"chmod|chown|rename|renames|replace|truncate|utime|access)$"
    r"|^shutil\.(?:copy|copy2|copyfile|copytree|move|rmtree)$"
)
CODE_FN = re.compile(r"^(?:eval|exec|compile)$")
DESER_FN = re.compile(
    r"^(?:c?[Pp]ickle|_pickle|dill|cloudpickle)\.(?:loads?|Unpickler)$|^marshal\.loads?$"
    r"|^jsonpickle\.(?:decode|loads)$|^yaml\.(?:unsafe_load|unsafe_load_all|full_load|full_load_all)$"
)
YAML_LOAD_FN = re.compile(r"^yaml\.(?:load|load_all)$")
SHELL_CMD_FN = re.compile(r"^subprocess\.(?:call|run|Popen|check_output|check_call)$")
PATH_METHODS = frozenset(
    {
        "exists",
        "is_file",
        "is_dir",
        "open",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "unlink",
        "mkdir",
        "rmdir",
        "iterdir",
        "glob",
        "rglob",
        "stat",
        "touch",
        "rename",
        "replace",
        "chmod",
        "symlink_to",
        "hardlink_to",
    }
)
PATH_CTORS = frozenset({"Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath"})
NORMALIZERS = frozenset(
    {"os.path.realpath", "os.path.abspath", "os.path.normpath", "posixpath.realpath"}
)
LDAP_SEARCH = frozenset({"search", "search_s", "search_st", "search_ext", "search_ext_s"})
XML_PARSE = frozenset({"parseString", "parse", "fromstring", "XML", "iterparse", "XMLID"})
REDIRECT_FNS = frozenset(
    {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse"}
)
MARKUP_FNS = frozenset({"Markup", "mark_safe", "SafeString", "SafeText"})
DJANGO_RESPONSES = frozenset(
    {
        "HttpResponse",
        "HttpResponseBadRequest",
        "HttpResponseNotFound",
        "HttpResponseForbidden",
        "HttpResponseServerError",
    }
)
WEAK_RANDOM_FUNCS = frozenset(
    {
        "random",
        "randint",
        "randrange",
        "choice",
        "choices",
        "getrandbits",
        "randbytes",
        "uniform",
        "normalvariate",
        "gauss",
        "sample",
        "shuffle",
        "triangular",
        "betavariate",
        "expovariate",
        "gammavariate",
        "lognormvariate",
        "vonmisesvariate",
        "paretovariate",
        "weibullvariate",
        "binomialvariate",
    }
)
SESSION_RE = re.compile(r"(?:^|\.)session$")
#: Names that mark a value as a security token, credential or session secret.
SENSITIVE_RE = re.compile(
    r"(?i)token|secret|passw|pwd|nonce|(?:^|_)salt(?:_|$)|(?:^|_)otp(?:_|$)|csrf|xsrf|"
    r"api_?key|session|cookie|reset_?code|verification_?code|one_?time|captcha|activation"
)
ROUTE_DECORATOR = re.compile(r"(?:^|\.)route\s*\(")
METHOD_DECORATOR = re.compile(r"\.(?:get|post|put|patch|delete)\s*\(")
_ROUTE_RULE = re.compile(r"\(\s*(['\"])([^'\"\n]*)\1")
_REQUEST_PATH = frozenset({"request.path", "flask.request.path"})
_IMPORTS_FLASK = re.compile(rb"(?m)^\s*(?:from|import)\s+(?:flask|quart|bottle)\b")
_IMPORTS_JSON_FRAMEWORK = re.compile(rb"(?m)^\s*(?:from|import)\s+(?:fastapi|starlette)\b")
_IMPORTS_LDAP = re.compile(rb"(?m)^\s*(?:from|import)\s+ldap3?\b")
_IMPORTS_XML = re.compile(rb"(?m)^\s*(?:from|import)\s+(?:lxml|xml\.etree|elementpath)\b")
_FROM_RANDOM = re.compile(rb"(?m)^\s*from\s+random\s+import\s+([^\n#]+)")
_EXTERNAL_ENTITY_FEATURE = re.compile(r"external[-_](?:ges|pes|general|parameter)")
_QUOTES = frozenset({"'", '"'})


@dataclass(frozen=True)
class Val:
    """Abstract value of one expression or variable."""

    taint: bool = False
    clean: frozenset[str] = frozenset()
    lit: bool = False
    const: Any = NOCONST
    weak: bool = False
    param: bool = False
    flags: frozenset[str] = frozenset()
    elems: tuple[tuple[Any, Val], ...] | None = None
    seq: tuple[Val, ...] | None = None

    def tainted_for(self, cwes: frozenset[str]) -> bool:
        return self.taint and not (cwes & self.clean)


UNKNOWN = Val()
LIT = Val(lit=True)
TAINT = Val(taint=True)


def combine(vals: Iterable[Val]) -> Val:
    """A value computed from all of ``vals`` (taint if any, literal if all)."""
    taint = weak = param = False
    lit = True
    clean: frozenset[str] | None = None
    for v in vals:
        if v.taint:
            taint = True
            clean = v.clean if clean is None else clean & v.clean
        weak = weak or v.weak
        param = param or v.param
        lit = lit and v.lit
    return Val(
        taint=taint,
        clean=(clean if clean is not None else frozenset()) if taint else frozenset(),
        lit=lit,
        weak=weak,
        param=param,
    )


def derived(v: Val, **changes: Any) -> Val:
    """A new value computed from ``v`` alone: same taint, origin and literalness."""
    out = Val(taint=v.taint, clean=v.clean, lit=v.lit, weak=v.weak, param=v.param)
    return replace(out, **changes) if changes else out


def summary(v: Val) -> Val:
    """``v`` without its constant, flags and element structure."""
    if v.const is NOCONST and not v.flags and v.elems is None and v.seq is None:
        return v
    return derived(v)


def elem_of(v: Val) -> Val:
    """The value of one element when iterating over ``v``."""
    if v.seq is not None:
        return combine(v.seq) if v.seq else Val(lit=True)
    if v.elems is not None:
        return Val(lit=True)  # iterating a dict yields its (constant) keys
    return derived(v)


def _same_const(a: Any, b: Any) -> bool:
    if a is NOCONST or b is NOCONST or type(a) is not type(b):
        return False
    try:
        return bool(a == b)
    except Exception:  # pragma: no cover - consts are plain literals
        return False


def join(a: Val, b: Val) -> Val:
    """Least upper bound of two values reaching the same point."""
    if a is b or a == b:
        return a
    if a.taint and b.taint:
        clean = a.clean & b.clean
    elif a.taint:
        clean = a.clean
    elif b.taint:
        clean = b.clean
    else:
        clean = frozenset()
    elems: tuple[tuple[Any, Val], ...] | None = None
    if a.elems is not None and b.elems is not None:
        merged: dict[Any, Val] = {}
        for k, v in a.elems:
            merged[k] = v
        for k, v in b.elems:
            merged[k] = join(merged[k], v) if k in merged else v
        elems = tuple(merged.items())
    seq: tuple[Val, ...] | None = None
    if a.seq is not None and b.seq is not None and len(a.seq) == len(b.seq):
        seq = tuple(join(x, y) for x, y in zip(a.seq, b.seq, strict=True))
    return Val(
        taint=a.taint or b.taint,
        clean=clean,
        lit=a.lit and b.lit,
        const=a.const if _same_const(a.const, b.const) else NOCONST,
        weak=a.weak or b.weak,
        param=a.param or b.param,
        flags=a.flags | b.flags,
        elems=elems,
        seq=seq,
    )


class State:
    """Variable -> value at one program point. ``live`` is False after a return."""

    __slots__ = ("vars", "live")

    def __init__(self, vars: dict[str, Val] | None = None, live: bool = True) -> None:
        self.vars: dict[str, Val] = vars if vars is not None else {}
        self.live = live

    def copy(self) -> State:
        return State(dict(self.vars), self.live)

    def get(self, name: str) -> Val:
        return self.vars.get(name, UNKNOWN)


DEAD = State(live=False)


def join_states(states: Iterable[State]) -> State:
    live = [s for s in states if s.live]
    if not live:
        return State(live=False)
    if len(live) == 1:
        return live[0].copy()
    names: set[str] = set()
    for s in live:
        names.update(s.vars)
    out: dict[str, Val] = {}
    for n in names:
        v = live[0].vars.get(n, UNKNOWN)
        for s in live[1:]:
            v = join(v, s.vars.get(n, UNKNOWN))
        out[n] = v
    return State(out)


def truthy(value: Any) -> bool | None:
    if value is NOCONST:
        return None
    try:
        return bool(value)
    except Exception:  # pragma: no cover
        return None


def _fold_binary(op: str, a: Any, b: Any) -> Any:
    if a is NOCONST or b is NOCONST:
        return NOCONST
    num = (int, float)
    both_num = isinstance(a, num) and isinstance(b, num)
    same_text = (isinstance(a, str) and isinstance(b, str)) or (
        isinstance(a, bytes) and isinstance(b, bytes)
    )
    repeat = isinstance(a, str) and isinstance(b, int) and len(a) * max(b, 0) <= MAX_STR
    r: Any = NOCONST
    try:
        if op == "+" and (both_num or same_text):
            r = a + b
        elif op == "-" and both_num:
            r = a - b
        elif op == "*" and (both_num or repeat):
            r = a * b
        elif op in ("//", "%") and both_num and b != 0:
            r = a // b if op == "//" else a % b
        elif op == "/" and both_num and b != 0:
            r = a / b
        elif op == "**" and isinstance(a, int) and isinstance(b, int) and 0 <= b <= 64:
            r = a**b if abs(a) <= 1 << 16 else NOCONST
    except Exception:
        return NOCONST
    if isinstance(r, (str, bytes)) and len(r) > MAX_STR:
        return NOCONST
    if isinstance(r, int) and abs(r) > 1 << 128:
        return NOCONST
    return r


def _fold_compare(op: str, a: Any, b: Any) -> Any:
    try:
        if op == "==":
            return a == b
        if op == "!=":
            return a != b
        if op == "<":
            return a < b
        if op == ">":
            return a > b
        if op == "<=":
            return a <= b
        if op == ">=":
            return a >= b
        if op in ("in", "not in") and isinstance(b, (str, bytes, tuple, list, frozenset)):
            if isinstance(b, (str, bytes)) and not isinstance(a, type(b)):
                return NOCONST
            return (a in b) if op == "in" else (a not in b)
        if op in ("is", "is not") and (a is None or b is None or isinstance(a, bool)):
            return (a is b) if op == "is" else (a is not b)
    except Exception:
        return NOCONST
    return NOCONST


@dataclass
class _Call:
    node: Any
    fn: str
    last: str
    recv: Val | None
    recv_node: Any
    pos: list[Val]
    pos_nodes: list[Any]
    kw: dict[str, Val]
    kw_nodes: dict[str, Any]
    extra: list[Val]

    def arg(self, index: int, *names: str) -> Val | None:
        if index < len(self.pos):
            return self.pos[index]
        for n in names:
            if n in self.kw:
                return self.kw[n]
        return None

    def every_arg(self) -> list[Val]:
        return [*self.pos, *self.kw.values(), *self.extra]


@dataclass
class _FnCtx:
    name: str
    route: bool
    sensitive: bool
    static_path: bool = False
    returns: list[Val] = field(default_factory=list)


#: ``emit(sink_id, node)``: report a finding for ``sink_id`` at ``node``.
Emit = Callable[[str, Any], None]


class Flow:
    """One analysis run over one file (or one function body)."""

    def __init__(
        self,
        src: bytes,
        emit: Emit | None,
        *,
        context: LanguageContext | None = None,
        source_methods: frozenset[str] = frozenset(),
        source_functions: frozenset[str] = frozenset(),
    ) -> None:
        self._src = src
        self._emit_cb = emit
        self._ctx = context
        self._cwes: frozenset[str] = TAINT_CWES | (context.cwes if context else frozenset())
        self.source_methods = source_methods
        self.source_functions = source_functions
        self._fn_stack: list[_FnCtx] = []
        self._loop_stack: list[list[tuple[str, State]]] = []
        self._quiet = 0
        self._steps = 0
        self._module_consts: dict[str, Val] = {}
        #: (kind, line) -> "tainted" | "literal" | "unknown", for the regex tier.
        self.verdicts: dict[tuple[str, int], str] = {}
        self._flask = bool(_IMPORTS_FLASK.search(src))
        self._json_framework = bool(_IMPORTS_JSON_FRAMEWORK.search(src))
        self._ldap = bool(_IMPORTS_LDAP.search(src))
        self._xml = bool(_IMPORTS_XML.search(src))
        self._random_names: set[str] = set()
        for m in _FROM_RANDOM.finditer(src):
            for part in m.group(1).decode("utf-8", "ignore").replace("(", " ").split(","):
                bits = part.split()
                if bits and bits[0] in WEAK_RANDOM_FUNCS:
                    self._random_names.add(bits[-1])
        self._ev_table: dict[str, Callable[[Any, State, int], Val]] = {
            "identifier": self._ev_identifier,
            "attribute": self._ev_attribute,
            "call": self._ev_call,
            "string": self._ev_string,
            "concatenated_string": self._ev_concat,
            "integer": self._ev_number,
            "float": self._ev_number,
            "true": lambda n, s, d: Val(lit=True, const=True),
            "false": lambda n, s, d: Val(lit=True, const=False),
            "none": lambda n, s, d: Val(lit=True, const=None),
            "ellipsis": lambda n, s, d: LIT,
            "parenthesized_expression": self._ev_paren,
            "binary_operator": self._ev_binary,
            "unary_operator": self._ev_unary,
            "not_operator": self._ev_not,
            "comparison_operator": self._ev_compare,
            "boolean_operator": self._ev_boolean,
            "conditional_expression": self._ev_conditional,
            "subscript": self._ev_subscript,
            "list": self._ev_sequence,
            "tuple": self._ev_sequence,
            "expression_list": self._ev_sequence,
            "set": self._ev_set,
            "dictionary": self._ev_dict,
            "list_comprehension": self._ev_comprehension,
            "set_comprehension": self._ev_comprehension,
            "generator_expression": self._ev_comprehension,
            "dictionary_comprehension": self._ev_comprehension,
            "pair": self._ev_pair,
            "lambda": lambda n, s, d: UNKNOWN,
            "named_expression": self._ev_walrus,
            "keyword_argument": self._ev_keyword,
            "list_splat": self._ev_splat,
            "dictionary_splat": self._ev_splat,
        }

    # --- entry points -------------------------------------------------------
    def run(self, root) -> None:
        self._module_consts = self._module_constants(root)
        self._exec_block(root, State(), 0)

    def _module_constants(self, root) -> dict[str, Val]:
        """Module-level names bound once to an immutable literal (``CMD = "ls"``).

        Functions see these as literal values. A name assigned more than once at
        module level, or declared ``global`` anywhere, is left out.
        """
        counts: dict[str, int] = {}
        found: dict[str, Val] = {}
        for stmt in root.named_children:
            if stmt.type != "expression_statement":
                continue
            for ch in stmt.named_children:
                if ch.type not in ("assignment", "augmented_assignment"):
                    continue
                left = ch.child_by_field_name("left")
                right = ch.child_by_field_name("right")
                if left is None or left.type != "identifier":
                    continue
                name = self.text(left)
                counts[name] = counts.get(name, 0) + 1
                if (
                    ch.type == "assignment"
                    and right is not None
                    and right.type in _IMMUTABLE_LITERALS
                ):
                    v = self._ev_quiet(right, State())
                    if v.lit and not v.taint and not v.weak:
                        found[name] = v
        if not found:
            return {}
        declared_global: set[str] = set()
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "global_statement":
                declared_global.update(self.text(c) for c in n.named_children)
            stack.extend(n.children)
        return {n: v for n, v in found.items() if counts[n] == 1 and n not in declared_global}

    def run_body(self, body, seeds: Iterable[str]) -> None:
        self._exec_block(body, State({n: TAINT for n in seeds}), 0)

    def function_returns_taint(self, fn_node) -> bool:
        """Whether ``fn_node`` returns an untrusted value with nothing seeded."""
        body = fn_node.child_by_field_name("body")
        if body is None:
            return False
        ctx = _FnCtx(name="", route=False, sensitive=False)
        self._fn_stack.append(ctx)
        try:
            self._exec_block(body, State(), 0)
        finally:
            self._fn_stack.pop()
        return any(v.taint for v in ctx.returns)

    # --- helpers ------------------------------------------------------------
    def text(self, node) -> str:
        return self._src[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def _compact(self, node) -> str:
        return re.sub(r"\s+", "", self.text(node))

    def _path(self, node) -> str | None:
        """Dotted name of an identifier/attribute chain (``a.b.c``), else None."""
        parts: list[str] = []
        cur = node
        while cur is not None and cur.type == "attribute":
            attr = cur.child_by_field_name("attribute")
            if attr is None:
                return None
            parts.append(self.text(attr))
            cur = cur.child_by_field_name("object")
        if cur is None or cur.type != "identifier":
            return None
        parts.append(self.text(cur))
        return ".".join(reversed(parts))

    def _is_source(self, text: str) -> bool:
        if self._ctx is not None:
            text = self._ctx.mask_trusted(text)
        return bool(SOURCE_RE.search(text))

    def _emit(self, sink_id: str, node) -> None:
        if self._emit_cb is not None and not self._quiet:
            self._emit_cb(sink_id, node)

    def _ev_quiet(self, node, st: State) -> Val:
        """Evaluate ``node`` again (for a guard) without reporting sinks twice."""
        self._quiet += 1
        try:
            return self.ev(node, st, 0)
        finally:
            self._quiet -= 1

    def _literal(self, node) -> Any:
        text = self.text(node)
        if len(text) > MAX_LITERAL_TEXT:
            return NOCONST
        try:
            value = _pyast.literal_eval(text)
        except Exception:
            return NOCONST
        if isinstance(value, (str, bytes, int, float, bool)) or value is None:
            return value
        return NOCONST

    def _verdict(self, kind: str, node, v: Val | None) -> None:
        if v is None:
            return
        line = node.start_point[0] + 1
        if v.taint:
            new = "tainted"
        elif v.lit:
            new = "literal"
        else:
            new = "unknown"
        rank = {"literal": 0, "unknown": 1, "tainted": 2}
        old = self.verdicts.get((kind, line))
        if old is None or rank[new] > rank[old]:
            self.verdicts[(kind, line)] = new

    # --- statements ---------------------------------------------------------
    def _exec_block(self, block, st: State, depth: int) -> State:
        for stmt in block.named_children:
            if not st.live:
                break
            st = self._exec_stmt(stmt, st, depth)
        return st

    def _exec_stmt(self, node, st: State, depth: int) -> State:
        self._steps += 1
        if self._steps > MAX_STEPS:
            raise AnalysisBudgetExceeded(f"more than {MAX_STEPS} statement visits")
        t = node.type
        if depth > MAX_STMT_DEPTH:
            self._flat(node, st)
            return st
        if t == "expression_statement":
            for ch in node.named_children:
                self._exec_expr_stmt(ch, st)
            return st
        if t == "if_statement":
            return self._exec_if(node, st, depth)
        if t == "for_statement":
            return self._exec_for(node, st, depth)
        if t == "while_statement":
            return self._exec_while(node, st, depth)
        if t == "try_statement":
            return self._exec_try(node, st, depth)
        if t == "with_statement":
            return self._exec_with(node, st, depth)
        if t == "match_statement":
            return self._exec_match(node, st, depth)
        if t == "function_definition":
            self._exec_function(node, [], depth)
            return st
        if t == "class_definition":
            body = node.child_by_field_name("body")
            if body is not None:
                self._exec_block(body, State(), depth + 1)
            return st
        if t == "decorated_definition":
            decorators = [self.text(c) for c in node.named_children if c.type == "decorator"]
            defn = node.child_by_field_name("definition")
            if defn is not None and defn.type == "function_definition":
                self._exec_function(defn, decorators, depth)
            elif defn is not None:
                self._exec_stmt(defn, st, depth)
            return st
        if t == "return_statement":
            self._exec_return(node, st)
            return State(live=False)
        if t == "raise_statement":
            for ch in node.named_children:
                self.ev(ch, st, 0)
            return State(live=False)
        if t in ("break_statement", "continue_statement"):
            if self._loop_stack:
                kind = "break" if t == "break_statement" else "continue"
                self._loop_stack[-1].append((kind, st.copy()))
            return State(live=False)
        if t == "assert_statement":
            named = node.named_children
            if named:
                self.ev(named[0], st, 0)
                self._refine(named[0], st, True)
            return st
        if t == "block":
            return self._exec_block(node, st, depth + 1)
        if t in (
            "import_statement",
            "import_from_statement",
            "future_import_statement",
            "global_statement",
            "nonlocal_statement",
            "pass_statement",
            "comment",
            "type_alias_statement",
        ):
            return st
        for ch in node.named_children:
            self.ev(ch, st, 0)
        return st

    def _exec_expr_stmt(self, node, st: State) -> None:
        t = node.type
        if t == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            targets = [left] if left is not None else []
            while right is not None and right.type == "assignment":
                nxt = right.child_by_field_name("left")
                if nxt is not None:
                    targets.append(nxt)
                right = right.child_by_field_name("right")
            if right is None:
                return
            val = self.ev(right, st, 0)
            for target in targets:
                self._assign(target, val, st)
            return
        if t == "augmented_assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")
            if left is None or right is None:
                return
            val = self.ev(right, st, 0)
            cur = self.ev(left, st, 0)
            op = self.text(op_node)[:-1] if op_node is not None else "+"
            self._assign(left, self._binop(op, cur, val), st)
            return
        self.ev(node, st, 0)

    def _assign(self, target, val: Val, st: State) -> None:
        t = target.type
        if t == "identifier":
            name = self.text(target)
            if val.weak and SENSITIVE_RE.search(name):
                self._emit("ast-weak-random", target)
            st.vars[name] = val
            self._kill_prefix(st, name)
            return
        if t == "attribute":
            path = self._path(target)
            attr = target.child_by_field_name("attribute")
            if val.weak and attr is not None and SENSITIVE_RE.search(self.text(attr)):
                self._emit("ast-weak-random", target)
            if path is None:
                obj = target.child_by_field_name("object")
                if obj is not None:
                    self.ev(obj, st, 0)
                return
            st.vars[path] = val
            self._kill_prefix(st, path)
            return
        if t == "subscript":
            base = target.child_by_field_name("value")
            idx_node = target.child_by_field_name("subscript")
            if base is None:
                return
            idx = self.ev(idx_node, st, 0) if idx_node is not None else UNKNOWN
            base_text = self._compact(base)
            if SESSION_RE.search(base_text) and (
                val.tainted_for(SINK_CWES["ast-trust-boundary"])
                or idx.tainted_for(SINK_CWES["ast-trust-boundary"])
            ):
                self._emit("ast-trust-boundary", target)
            if (
                base_text.endswith("headers")
                and isinstance(idx.const, str)
                and idx.const.lower() == "location"
                and val.tainted_for(SINK_CWES["ast-open-redirect"])
            ):
                self._emit("ast-open-redirect", target)  # resp.headers["Location"] = url
            if val.weak and (
                SENSITIVE_RE.search(base_text)
                or (isinstance(idx.const, str) and SENSITIVE_RE.search(idx.const))
            ):
                self._emit("ast-weak-random", target)
            path = self._path(base)
            if path is None:
                self.ev(base, st, 0)
                return
            st.vars[path] = self._store_elem(st.get(path), idx, val)
            return
        if t in (
            "pattern_list",
            "tuple_pattern",
            "list_pattern",
            "tuple",
            "list",
            "expression_list",
        ):
            elts = [c for c in target.named_children if c.type != "comment"]
            splat = any(c.type == "list_splat_pattern" for c in elts)
            if val.seq is not None and len(val.seq) == len(elts) and not splat:
                for e, v in zip(elts, val.seq, strict=True):
                    self._assign(e, v, st)
            else:
                each = elem_of(val)
                for e in elts:
                    self._assign(e, each, st)
            return
        if t in ("list_splat_pattern", "parenthesized_expression"):
            for c in target.named_children:
                self._assign(c, summary(val), st)
            return

    @staticmethod
    def _kill_prefix(st: State, name: str) -> None:
        prefix = name + "."
        dead = [k for k in st.vars if k.startswith(prefix)]
        for k in dead:
            del st.vars[k]

    @staticmethod
    def _hashable_const(v: Val) -> bool:
        return v.const is not NOCONST and isinstance(v.const, (str, bytes, int, float, bool, tuple))

    def _store_elem(self, cur: Val, idx: Val, val: Val) -> Val:
        """``cur[idx] = val`` on a tracked container, or a collapsed value."""
        if cur.elems is not None and self._hashable_const(idx):
            items = dict(cur.elems)
            items[idx.const] = val
            if len(items) <= MAX_ITEMS:
                return self._dict_val(items, cur.flags)
        if (
            cur.seq is not None
            and isinstance(idx.const, int)
            and not isinstance(idx.const, bool)
            and -len(cur.seq) <= idx.const < len(cur.seq)
        ):
            seq = list(cur.seq)
            seq[idx.const] = val
            return self._seq_val(seq, cur.flags)
        merged = combine([summary(cur), summary(val)])
        return replace(merged, flags=cur.flags)

    @staticmethod
    def _dict_val(items: dict[Any, Val], flags: frozenset[str] = frozenset()) -> Val:
        base = combine(items.values())
        return replace(base, elems=tuple(items.items()), flags=flags)

    @staticmethod
    def _seq_val(seq: list[Val], flags: frozenset[str] = frozenset()) -> Val:
        base = combine(seq)
        if len(seq) > MAX_ITEMS:
            return replace(base, flags=flags)
        return replace(base, seq=tuple(seq), flags=flags)

    def _exec_if(self, node, st: State, depth: int) -> State:
        chain: list[tuple[Any, Any]] = []
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        if cond is not None and cons is not None:
            chain.append((cond, cons))
        else_body = None
        for i, ch in enumerate(node.children):
            if node.field_name_for_child(i) != "alternative":
                continue
            if ch.type == "elif_clause":
                c = ch.child_by_field_name("condition")
                b = ch.child_by_field_name("consequence")
                if c is not None and b is not None:
                    chain.append((c, b))
            elif ch.type == "else_clause":
                else_body = ch.child_by_field_name("body")
        results: list[State] = []
        pending: State | None = st
        for c, body in chain:
            assert pending is not None
            truth = truthy(self.ev(c, pending, 0).const)
            if truth is not False:
                s_true = pending.copy()
                if truth is None:
                    self._refine(c, s_true, True)
                results.append(self._exec_block(body, s_true, depth + 1))
            if truth is True:
                pending = None
                break
            if truth is None:
                pending = pending.copy()
                self._refine(c, pending, False)
        if pending is not None:
            if else_body is not None:
                results.append(self._exec_block(else_body, pending, depth + 1))
            else:
                results.append(pending)
        return join_states(results)

    def _loop(self, st: State, depth: int, body, bind: Callable[[State], None]) -> State:
        exits: list[tuple[str, State]] = []
        # Nested loops would multiply the rounds (3**depth), so only the two
        # outermost loops iterate towards a fixed point; deeper ones run once.
        rounds = LOOP_ROUNDS if len(self._loop_stack) < 2 else 1
        self._loop_stack.append(exits)
        head = st
        try:
            for _ in range(rounds):
                s = head.copy()
                bind(s)
                out = self._exec_block(body, s, depth + 1)
                conts = [x for k, x in exits if k == "continue"]
                new_head = join_states([head, out, *conts])
                if new_head.live == head.live and new_head.vars == head.vars:
                    break
                head = new_head
        finally:
            self._loop_stack.pop()
        breaks = [x for k, x in exits if k == "break"]
        return join_states([head, *breaks]) if breaks else head

    def _exec_for(self, node, st: State, depth: int) -> State:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        body = node.child_by_field_name("body")
        if body is None:
            return st
        it = self.ev(right, st, 0) if right is not None else UNKNOWN
        elem = elem_of(it)

        def bind(s: State) -> None:
            if left is not None:
                self._assign(left, elem, s)

        after = self._loop(st, depth, body, bind)
        alt = node.child_by_field_name("alternative")
        if alt is not None:
            else_body = alt.child_by_field_name("body")
            if else_body is not None and after.live:
                after = self._exec_block(else_body, after, depth + 1)
        return after

    def _exec_while(self, node, st: State, depth: int) -> State:
        cond = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if cond is None or body is None:
            return st
        truth = truthy(self.ev(cond, st, 0).const)
        if truth is False:
            return st

        def bind(s: State) -> None:
            self.ev(cond, s, 0)
            if truth is None:
                self._refine(cond, s, True)

        after = self._loop(st, depth, body, bind)
        if truth is True:
            # ``while True``: only a break leaves the loop. _loop folded the
            # break states in; without any the code after it is unreachable.
            return after if self._has_break(body) else State(live=False)
        return after

    def _has_break(self, body) -> bool:
        stack = [body]
        while stack:
            n = stack.pop()
            if n.type == "break_statement":
                return True
            if n.type in (
                "for_statement",
                "while_statement",
                "function_definition",
                "class_definition",
            ):
                continue
            stack.extend(n.children)
        return False

    def _exec_try(self, node, st: State, depth: int) -> State:
        body = node.child_by_field_name("body")
        if body is None:
            return st
        out = self._exec_block(body, st.copy(), depth + 1)
        handler_entry = join_states([st, out])
        results: list[State] = []
        normal = out
        finally_block = None
        for ch in node.named_children:
            if ch.type == "else_clause":
                else_body = ch.child_by_field_name("body")
                if else_body is not None and normal.live:
                    normal = self._exec_block(else_body, normal, depth + 1)
            elif ch.type in ("except_clause", "except_group_clause"):
                s = handler_entry.copy()
                block = None
                for sub in ch.named_children:
                    if sub.type == "block":
                        block = sub
                    elif sub.type == "as_pattern":
                        alias = sub.child_by_field_name("alias")
                        if alias is not None:
                            for name in alias.named_children:
                                self._assign(name, UNKNOWN, s)
                if block is not None:
                    results.append(self._exec_block(block, s, depth + 1))
                else:
                    results.append(s)
            elif ch.type == "finally_clause":
                finally_block = next((c for c in ch.named_children if c.type == "block"), None)
        results.insert(0, normal)
        merged = join_states(results)
        if finally_block is not None:
            base = merged if merged.live else handler_entry.copy()
            fin = self._exec_block(finally_block, base, depth + 1)
            return fin if merged.live else State(live=False)
        return merged

    def _exec_with(self, node, st: State, depth: int) -> State:
        for ch in node.named_children:
            if ch.type != "with_clause":
                continue
            for item in ch.named_children:
                value = item.child_by_field_name("value")
                if value is None:
                    continue
                if value.type == "as_pattern":
                    named = value.named_children
                    v = self.ev(named[0], st, 0) if named else UNKNOWN
                    alias = value.child_by_field_name("alias")
                    if alias is not None:
                        for name in alias.named_children:
                            self._assign(name, v, st)
                else:
                    self.ev(value, st, 0)
        body = node.child_by_field_name("body")
        return self._exec_block(body, st, depth + 1) if body is not None else st

    def _exec_match(self, node, st: State, depth: int) -> State:
        subject = node.child_by_field_name("subject")
        body = node.child_by_field_name("body")
        if body is None:
            return st
        sv = self.ev(subject, st, 0) if subject is not None else UNKNOWN
        results: list[State] = []
        exhaustive = False
        for case in body.named_children:
            if case.type != "case_clause":
                continue
            pats = [c for c in case.named_children if c.type == "case_pattern"]
            cons = case.child_by_field_name("consequence")
            guard = case.child_by_field_name("guard")
            decided = self._match_static(pats, sv)
            if decided is False or cons is None:
                continue
            s = st.copy()
            for p in pats:
                for name in self._capture_names(p):
                    s.vars[name] = summary(sv)
            if guard is not None:
                g = guard.named_children[0] if guard.named_children else None
                if g is not None and truthy(self.ev(g, s, 0).const) is False:
                    continue
            results.append(self._exec_block(cons, s, depth + 1))
            if decided is True and guard is None:
                exhaustive = True
                break
        if not exhaustive:
            results.append(st)
        return join_states(results)

    def _match_static(self, pats: list[Any], sv: Val) -> bool | None:
        if len(pats) != 1:
            return None
        p = pats[0]
        named = [c for c in p.named_children if c.type != "comment"]
        if not named:
            return True if self.text(p).strip() == "_" else None
        if len(named) != 1:
            return None
        inner = named[0]
        if inner.type == "identifier":
            return True  # a capture pattern always matches
        options = inner.named_children if inner.type == "union_pattern" else [inner]
        values = []
        for o in options:
            if o.type not in (
                "string",
                "integer",
                "float",
                "true",
                "false",
                "none",
                "concatenated_string",
            ):
                return None
            value = self._literal(o)
            if value is NOCONST:
                return None
            values.append(value)
        if sv.const is NOCONST:
            return None
        return any(_same_const(sv.const, v) for v in values)

    def _capture_names(self, pattern) -> list[str]:
        out: list[str] = []
        stack = [pattern]
        while stack:
            n = stack.pop()
            if (
                n.type == "identifier"
                and n.parent is not None
                and n.parent.type
                in (
                    "case_pattern",
                    "as_pattern_target",
                    "splat_pattern",
                    "keyword_pattern",
                    "list_pattern",
                    "tuple_pattern",
                )
            ):
                name = self.text(n)
                if name != "_":
                    out.append(name)
            stack.extend(n.named_children)
        return out

    def _exec_function(self, node, decorators: list[str], depth: int) -> None:
        body = node.child_by_field_name("body")
        name_node = node.child_by_field_name("name")
        if body is None:
            return
        name = self.text(name_node) if name_node is not None else ""
        route = any(ROUTE_DECORATOR.search(d) for d in decorators) or (
            self._flask
            and not self._json_framework
            and any(METHOD_DECORATOR.search(d) for d in decorators)
        )
        ctx = _FnCtx(
            name=name,
            route=route,
            sensitive=bool(SENSITIVE_RE.search(name)),
            static_path=route and self._static_routes(decorators),
        )
        self._fn_stack.append(ctx)
        try:
            scope = {**self._module_consts, **self._param_vals(node)}
            self._exec_block(body, State(scope), depth + 1)
        finally:
            self._fn_stack.pop()

    @staticmethod
    def _static_routes(decorators: list[str]) -> bool:
        """Every route rule on the view is a literal path without ``<converters>``.

        Routing only dispatches a request to such a view when its path equals
        one of those literals, so ``request.path`` is not attacker-controlled
        there (its query string and headers still are).
        """
        rules = [d for d in decorators if ROUTE_DECORATOR.search(d) or METHOD_DECORATOR.search(d)]
        if not rules:
            return False
        for d in rules:
            m = _ROUTE_RULE.search(d)
            if m is None or "<" in m.group(2):
                return False
        return True

    def _param_vals(self, fn_node) -> dict[str, Val]:
        """Each parameter (except ``self``/``cls``) as a value of caller origin."""
        params = fn_node.child_by_field_name("parameters")
        out: dict[str, Val] = {}
        if params is None:
            return out
        for p in params.named_children:
            name = p if p.type == "identifier" else p.child_by_field_name("name")
            if name is None:
                name = next((c for c in p.named_children if c.type == "identifier"), None)
            if name is None:
                continue
            text = self.text(name)
            if text not in ("self", "cls"):
                out[text] = Val(param=True)
        return out

    def _exec_return(self, node, st: State) -> None:
        named = node.named_children
        v = self.ev(named[0], st, 0) if named else Val(lit=True, const=None)
        if not self._fn_stack:
            return
        ctx = self._fn_stack[-1]
        ctx.returns.append(v)
        if ctx.route and v.tainted_for(SINK_CWES["ast-xss"]):
            self._emit("ast-xss", node)
        if ctx.sensitive and v.weak:
            self._emit("ast-weak-random", node)

    # --- guards -------------------------------------------------------------
    def _atoms(self, cond, truth: bool, out: list[tuple[Any, bool]], depth: int = 0) -> None:
        """Atomic conditions implied by ``cond`` having the value ``truth``."""
        if depth > 20:
            return
        t = cond.type
        if t == "parenthesized_expression" and cond.named_children:
            self._atoms(cond.named_children[0], truth, out, depth + 1)
            return
        if t == "not_operator":
            arg = cond.child_by_field_name("argument")
            if arg is not None:
                self._atoms(arg, not truth, out, depth + 1)
            return
        if t == "boolean_operator":
            op_node = cond.child_by_field_name("operator")
            op = self.text(op_node) if op_node is not None else ""
            if (op == "and" and truth) or (op == "or" and not truth):
                for side in ("left", "right"):
                    sub = cond.child_by_field_name(side)
                    if sub is not None:
                        self._atoms(sub, truth, out, depth + 1)
            return
        out.append((cond, truth))

    def _refine(self, cond, st: State, truth: bool) -> None:
        atoms: list[tuple[Any, bool]] = []
        self._atoms(cond, truth, atoms)
        starts: set[tuple[str, str]] = set()
        ends: set[tuple[str, str]] = set()
        inner: set[tuple[str, str]] = set()
        for node, holds in atoms:
            contained = self._path_contained(node, st, 0) if holds else None
            if contained is not None:
                self._clean(st, contained, frozenset({CWE_PATH}))
            if node.type == "comparison_operator":
                self._refine_compare(node, st, holds, inner)
            elif node.type == "call":
                self._refine_call(node, st, holds, starts, ends)
        for key in starts & ends & inner:
            if key[1] in _QUOTES:
                self._clean(st, key[0], frozenset({CWE_CODE, "CWE-94"}))

    def _path_contained(self, node, st: State, depth: int) -> str | None:
        """The resolved path variable ``node`` proves to lie inside a base directory.

        Recognizes ``p.is_relative_to(base)``, ``str(p).startswith(base)``,
        ``p == base``, an ``or`` of such tests on the same ``p`` and
        ``any(<such a test> for base in bases)``, where ``p`` came from
        ``resolve()`` / ``os.path.realpath()`` (so ``..`` is already gone).
        """
        if depth > 8:
            return None
        t = node.type
        if t == "parenthesized_expression" and node.named_children:
            return self._path_contained(node.named_children[0], st, depth + 1)
        if t == "boolean_operator":
            op_node = node.child_by_field_name("operator")
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if op_node is None or self.text(op_node) != "or" or left is None or right is None:
                return None
            a = self._path_contained(left, st, depth + 1)
            return a if a is not None and a == self._path_contained(right, st, depth + 1) else None
        if t == "comparison_operator":
            operands = [c for c in node.named_children if c.type != "comment"]
            ops = [
                c.type
                for i, c in enumerate(node.children)
                if node.field_name_for_child(i) == "operators"
            ]
            if len(operands) == 2 and ops == ["=="]:
                p = self._path(self._unwrap(operands[0]))
                if p is not None and "normalized" in st.get(p).flags:
                    return p
            return None
        if t != "call":
            return None
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None:
            return None
        last = self._compact(fn).rsplit(".", 1)[-1]
        if last == "any" and args is not None and args.type == "generator_expression":
            body = args.child_by_field_name("body")
            return self._path_contained(body, st, depth + 1) if body is not None else None
        if last in ("is_relative_to", "startswith") and fn.type == "attribute":
            recv = fn.child_by_field_name("object")
            p = self._path(self._unwrap(recv)) if recv is not None else None
            if p is not None and "normalized" in st.get(p).flags:
                return p
        return None

    def _unwrap(self, node):
        """``x`` from ``str(x)`` / ``os.fspath(x)`` / ``(x)``, else ``node``."""
        for _ in range(4):
            if node.type == "parenthesized_expression" and node.named_children:
                node = node.named_children[0]
                continue
            if node.type == "call":
                fn = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")
                if (
                    fn is not None
                    and self._compact(fn) in ("str", "os.fspath", "bytes")
                    and args is not None
                    and len(args.named_children) == 1
                ):
                    node = args.named_children[0]
                    continue
            break
        return node

    def _refine_compare(self, node, st: State, holds: bool, inner: set[tuple[str, str]]) -> None:
        operands = [c for c in node.named_children if c.type != "comment"]
        ops = [
            c.type
            for i, c in enumerate(node.children)
            if node.field_name_for_child(i) == "operators"
        ]
        if len(operands) != 2 or len(ops) != 1:
            return
        a, b = operands
        op = ops[0]
        if op in ("in", "not in"):
            member_holds = (op == "in") == holds
            av = self._ev_quiet(a, st)
            if not member_holds and isinstance(av.const, str):
                target = b
                sliced = False
                if b.type == "subscript":
                    sub = b.child_by_field_name("subscript")
                    if sub is not None and sub.type == "slice" and self._compact(sub) == "1:-1":
                        target = b.child_by_field_name("value")
                        sliced = True
                path = self._path(target) if target is not None else None
                if path is not None:
                    if not sliced and ".." in av.const:
                        self._clean(st, path, frozenset({CWE_PATH}))
                    if not sliced and av.const in _QUOTES:
                        self._clean(st, path, frozenset({CWE_XPATH}))
                    if sliced and av.const in _QUOTES:
                        inner.add((path, av.const))
            if member_holds:
                bv = self._ev_quiet(b, st)
                if bv.lit:
                    path = self._path(a)
                    if path is not None:
                        st.vars[path] = Val(lit=True)
                    self._clean_url_host(a, st)
            return
        if op in ("==", "!="):
            eq_holds = (op == "==") == holds
            if not eq_holds:
                return
            for x, y in ((a, b), (b, a)):
                yv = self._ev_quiet(y, st)
                if yv.lit:
                    path = self._path(x)
                    if path is not None:
                        st.vars[path] = Val(lit=True, const=yv.const)
                    self._clean_url_host(x, st)

    def _clean_url_host(self, node, st: State) -> None:
        """``u.netloc`` / ``u.hostname`` known to be an allowed value."""
        if node.type != "attribute":
            return
        attr = node.child_by_field_name("attribute")
        obj = node.child_by_field_name("object")
        if attr is None or obj is None or self.text(attr) not in ("netloc", "hostname"):
            return
        if obj.type == "call":  # urlparse(target).netloc in ALLOWED
            fn = obj.child_by_field_name("function")
            args = obj.child_by_field_name("arguments")
            if fn is not None and self._compact(fn).rsplit(".", 1)[-1] in ("urlparse", "urlsplit"):
                first = next(
                    (a for a in (args.named_children if args else []) if a.type != "comment"), None
                )
                target = self._path(first) if first is not None else None
                if target is not None:
                    self._clean(st, target, frozenset({CWE_REDIRECT}))
            return
        path = self._path(obj)
        if path is None:
            return
        for flag in st.get(path).flags:
            if flag.startswith("urlof:"):
                self._clean(st, flag[6:], frozenset({CWE_REDIRECT}))

    def _refine_call(
        self,
        node,
        st: State,
        holds: bool,
        starts: set[tuple[str, str]],
        ends: set[tuple[str, str]],
    ) -> None:
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None:
            return
        last = self._compact(fn).rsplit(".", 1)[-1]
        recv = fn.child_by_field_name("object") if fn.type == "attribute" else None
        arg_nodes = (
            [c for c in args.named_children if c.type != "comment"] if args is not None else []
        )
        if not holds:
            return
        if recv is not None:
            rpath = self._path(self._unwrap(recv))
            if rpath is None:
                return
            if last in ("isdigit", "isnumeric", "isdecimal", "isalnum", "isalpha", "isidentifier"):
                v = st.get(rpath)
                st.vars[rpath] = Val(lit=True, weak=v.weak)
            elif last in ("startswith", "endswith") and len(arg_nodes) == 1:
                q = self._ev_quiet(arg_nodes[0], st).const
                if isinstance(q, str):
                    (starts if last == "startswith" else ends).add((rpath, q))
                if last == "startswith" and "normalized" in st.get(rpath).flags:
                    self._clean(st, rpath, frozenset({CWE_PATH}))
            elif last == "is_relative_to" and "normalized" in st.get(rpath).flags:
                self._clean(st, rpath, frozenset({CWE_PATH}))
        safe_url = ("url_has_allowed_host_and_scheme", "is_safe_url", "is_safe_redirect_url")
        if last in safe_url and arg_nodes:
            p = self._path(arg_nodes[0])
            if p is not None:
                self._clean(st, p, frozenset({CWE_REDIRECT}))

    @staticmethod
    def _clean(st: State, path: str, cwes: frozenset[str]) -> None:
        v = st.vars.get(path)
        if v is not None and v.taint:
            st.vars[path] = replace(v, clean=v.clean | cwes)

    # --- expressions --------------------------------------------------------
    def ev(self, node, st: State, depth: int) -> Val:
        if node is None:
            return UNKNOWN
        if depth > MAX_EXPR_DEPTH:
            return self._flat(node, st)
        handler = self._ev_table.get(node.type)
        if handler is not None:
            return handler(node, st, depth + 1)
        if node.type == "comment":
            return LIT
        vals = [self.ev(c, st, depth + 1) for c in node.named_children]
        v = combine(vals)
        return replace(v, lit=False)

    def _ev_identifier(self, node, st: State, depth: int) -> Val:
        return st.vars.get(self.text(node), UNKNOWN)

    def _ev_attribute(self, node, st: State, depth: int) -> Val:
        text = self._compact(node)
        if text in _REQUEST_PATH and self._fn_stack and self._fn_stack[-1].static_path:
            return LIT
        if self._is_source(text):
            return TAINT
        path = self._path(node)
        if path is not None:
            if path in st.vars:
                return st.vars[path]
            if path in _LIT_ATTRS:
                return LIT
        obj = self.ev(node.child_by_field_name("object"), st, depth)
        flags = obj.flags & {"reqobj"}
        attr = node.child_by_field_name("attribute")
        if attr is not None and self.text(attr) == "parent" and "path" in obj.flags:
            flags = flags | {"path"}
        return derived(obj, flags=flags)

    def _ev_string(self, node, st: State, depth: int) -> Val:
        start = node.children[0] if node.children else None
        prefix = (
            self.text(start).lower() if start is not None and start.type == "string_start" else ""
        )
        interps = [c for c in node.named_children if c.type == "interpolation"]
        if "f" in prefix:
            if not interps:
                return LIT
            vals: list[Val] = []
            for ip in interps:
                expr = ip.child_by_field_name("expression")
                if expr is not None:
                    vals.append(self.ev(expr, st, depth))
                for sub in ip.named_children:
                    if sub.type == "format_specifier":
                        for fe in sub.named_children:
                            e = fe.child_by_field_name("expression")
                            if e is not None:
                                vals.append(self.ev(e, st, depth))
            v = combine(vals)
            return replace(v, flags=frozenset() if v.lit else frozenset({"dyn"}))
        return Val(lit=True, const=self._literal(node))

    def _ev_concat(self, node, st: State, depth: int) -> Val:
        parts = [self.ev(c, st, depth) for c in node.named_children]
        v = combine(parts)
        consts = [p.const for p in parts]
        const: Any = NOCONST
        if consts and all(isinstance(c, str) for c in consts):
            const = "".join(consts)
        elif consts and all(isinstance(c, bytes) for c in consts):
            const = b"".join(consts)
        if isinstance(const, (str, bytes)) and len(const) > MAX_STR:
            const = NOCONST
        flags = frozenset() if v.lit else frozenset({"dyn"})
        return replace(v, const=const, flags=flags)

    def _ev_number(self, node, st: State, depth: int) -> Val:
        text = self.text(node)
        return Val(lit=True, const=self._literal(node) if len(text) < 40 else NOCONST)

    def _ev_paren(self, node, st: State, depth: int) -> Val:
        named = [c for c in node.named_children if c.type != "comment"]
        if len(named) == 1:
            return self.ev(named[0], st, depth)
        return combine(self.ev(c, st, depth) for c in named)

    def _binop(self, op: str, a: Val, b: Val) -> Val:
        v = combine([a, b])
        flags: set[str] = set()
        if op == "/" and "path" in a.flags:
            flags.add("path")
        if op in ("%", "+") and not v.lit:
            flags.add("dyn")
        if op == "+" and a.seq is not None and b.seq is not None:
            return self._seq_val([*a.seq, *b.seq])
        return replace(v, const=_fold_binary(op, a.const, b.const), flags=frozenset(flags))

    def _ev_binary(self, node, st: State, depth: int) -> Val:
        a = self.ev(node.child_by_field_name("left"), st, depth)
        b = self.ev(node.child_by_field_name("right"), st, depth)
        op_node = node.child_by_field_name("operator")
        return self._binop(self.text(op_node) if op_node is not None else "", a, b)

    def _ev_unary(self, node, st: State, depth: int) -> Val:
        v = self.ev(node.child_by_field_name("argument"), st, depth)
        op_node = node.child_by_field_name("operator")
        op = self.text(op_node) if op_node is not None else ""
        const: Any = NOCONST
        if isinstance(v.const, (int, float)) and not isinstance(v.const, bool):
            const = {"-": -v.const, "+": +v.const}.get(op, NOCONST)
            if op == "~" and isinstance(v.const, int):
                const = ~v.const
        return derived(v, const=const)

    def _ev_not(self, node, st: State, depth: int) -> Val:
        v = self.ev(node.child_by_field_name("argument"), st, depth)
        t = truthy(v.const)
        return Val(lit=v.lit, const=NOCONST if t is None else not t)

    def _ev_compare(self, node, st: State, depth: int) -> Val:
        operands = [c for c in node.named_children if c.type != "comment"]
        ops = [
            c.type
            for i, c in enumerate(node.children)
            if node.field_name_for_child(i) == "operators"
        ]
        vals = [self.ev(c, st, depth) for c in operands]
        lit = all(v.lit for v in vals)
        result: Any = NOCONST
        if len(ops) == len(vals) - 1 and all(v.const is not NOCONST for v in vals):
            result = True
            for i, op in enumerate(ops):
                r = _fold_compare(op, vals[i].const, vals[i + 1].const)
                if r is NOCONST:
                    result = NOCONST
                    break
                if not r:
                    result = False
                    break
        return Val(lit=lit, const=result)

    def _ev_boolean(self, node, st: State, depth: int) -> Val:
        left = self.ev(node.child_by_field_name("left"), st, depth)
        op_node = node.child_by_field_name("operator")
        op = self.text(op_node) if op_node is not None else ""
        t = truthy(left.const)
        if t is not None:
            if (op == "and" and not t) or (op == "or" and t):
                return left
            return self.ev(node.child_by_field_name("right"), st, depth)
        right = self.ev(node.child_by_field_name("right"), st, depth)
        return combine([left, right])

    def _ev_conditional(self, node, st: State, depth: int) -> Val:
        named = [c for c in node.named_children if c.type != "comment"]
        if len(named) != 3:
            return combine(self.ev(c, st, depth) for c in named)
        a, cond, b = named
        t = truthy(self.ev(cond, st, depth).const)
        if t is True:
            return self.ev(a, st, depth)
        if t is False:
            return self.ev(b, st, depth)
        return join(self.ev(a, st, depth), self.ev(b, st, depth))

    def _ev_subscript(self, node, st: State, depth: int) -> Val:
        value = node.child_by_field_name("value")
        subs = [
            c for i, c in enumerate(node.children) if node.field_name_for_child(i) == "subscript"
        ]
        vv = self.ev(value, st, depth)
        if len(subs) != 1:
            for s in subs:
                self.ev(s, st, depth)
            return summary(vv)
        idx_node = subs[0]
        if idx_node.type == "slice":
            slots: list[Any] = [None, None, None]
            known = True
            i = 0
            for ch in idx_node.children:
                if ch.type == ":":
                    i += 1
                elif ch.is_named and i < 3:
                    c = self.ev(ch, st, depth).const
                    if c is None or (isinstance(c, int) and not isinstance(c, bool)):
                        slots[i] = c
                    else:
                        known = False
            if known and isinstance(vv.const, (str, bytes)):
                return Val(lit=vv.lit, const=vv.const[slice(*slots)])
            if known and vv.seq is not None:
                return self._seq_val(list(vv.seq[slice(*slots)]))
            return summary(vv)
        iv = self.ev(idx_node, st, depth)
        if vv.seq is not None and isinstance(iv.const, int) and not isinstance(iv.const, bool):
            if -len(vv.seq) <= iv.const < len(vv.seq):
                return vv.seq[iv.const]
            return summary(vv)
        if vv.elems is not None and self._hashable_const(iv):
            for k, v in vv.elems:
                if _same_const(k, iv.const):
                    return v
            return UNKNOWN
        if (
            isinstance(vv.const, (str, bytes))
            and isinstance(iv.const, int)
            and not isinstance(iv.const, bool)
        ):
            try:
                return Val(lit=True, const=vv.const[iv.const])
            except IndexError:
                return summary(vv)
        return summary(vv)

    def _ev_sequence(self, node, st: State, depth: int) -> Val:
        elts: list[Val] = []
        splat = False
        for c in node.named_children:
            if c.type == "comment":
                continue
            if c.type in ("list_splat", "dictionary_splat", "parenthesized_list_splat"):
                splat = True
            elts.append(self.ev(c, st, depth))
        if splat or len(elts) > MAX_ITEMS:
            return combine(elts)
        return self._seq_val(elts)

    def _ev_set(self, node, st: State, depth: int) -> Val:
        return combine(self.ev(c, st, depth) for c in node.named_children if c.type != "comment")

    def _ev_dict(self, node, st: State, depth: int) -> Val:
        items: dict[Any, Val] = {}
        others: list[Val] = []
        ok = True
        for c in node.named_children:
            if c.type == "pair":
                k = self.ev(c.child_by_field_name("key"), st, depth)
                v = self.ev(c.child_by_field_name("value"), st, depth)
                if self._hashable_const(k):
                    items[k.const] = v
                else:
                    ok = False
                    others.extend([k, v])
            elif c.type != "comment":
                ok = False
                others.append(self.ev(c, st, depth))
        if ok and len(items) <= MAX_ITEMS:
            return self._dict_val(items)
        return combine([*items.values(), *others])

    def _ev_comprehension(self, node, st: State, depth: int) -> Val:
        inner = st.copy()
        iters: list[Val] = []
        for c in node.named_children:
            if c.type == "for_in_clause":
                it = self.ev(c.child_by_field_name("right"), inner, depth)
                iters.append(it)
                left = c.child_by_field_name("left")
                if left is not None:
                    self._assign(left, elem_of(it), inner)
            elif c.type == "if_clause":
                for sub in c.named_children:
                    self.ev(sub, inner, depth)
        body = node.child_by_field_name("body")
        bv = self.ev(body, inner, depth) if body is not None else UNKNOWN
        return derived(bv)

    def _ev_pair(self, node, st: State, depth: int) -> Val:
        return combine(
            [
                self.ev(node.child_by_field_name("key"), st, depth),
                self.ev(node.child_by_field_name("value"), st, depth),
            ]
        )

    def _ev_walrus(self, node, st: State, depth: int) -> Val:
        v = self.ev(node.child_by_field_name("value"), st, depth)
        name = node.child_by_field_name("name")
        if name is not None:
            self._assign(name, v, st)
        return v

    def _ev_keyword(self, node, st: State, depth: int) -> Val:
        return self.ev(node.child_by_field_name("value"), st, depth)

    def _ev_splat(self, node, st: State, depth: int) -> Val:
        named = node.named_children
        return summary(self.ev(named[0], st, depth)) if named else UNKNOWN

    # --- calls --------------------------------------------------------------
    def _ev_call(self, node, st: State, depth: int) -> Val:
        fn = node.child_by_field_name("function")
        argn = node.child_by_field_name("arguments")
        if fn is None:
            return UNKNOWN
        fn_text = self._compact(fn)
        last = fn_text.rsplit(".", 1)[-1]
        recv: Val | None = None
        recv_node = None
        if fn.type == "attribute":
            recv_node = fn.child_by_field_name("object")
            recv = self.ev(recv_node, st, depth)
        elif fn.type != "identifier":
            self.ev(fn, st, depth)
        pos: list[Val] = []
        pos_nodes: list[Any] = []
        kw: dict[str, Val] = {}
        kw_nodes: dict[str, Any] = {}
        extra: list[Val] = []
        if argn is not None:
            if argn.type == "generator_expression":
                pos.append(self.ev(argn, st, depth))
                pos_nodes.append(argn)
            else:
                for a in argn.named_children:
                    if a.type == "keyword_argument":
                        name = a.child_by_field_name("name")
                        value = a.child_by_field_name("value")
                        key = self.text(name) if name is not None else ""
                        kw[key] = self.ev(value, st, depth)
                        kw_nodes[key] = value
                    elif a.type in ("list_splat", "dictionary_splat"):
                        extra.append(self.ev(a, st, depth))
                    elif a.type != "comment":
                        pos.append(self.ev(a, st, depth))
                        pos_nodes.append(a)
        call = _Call(node, fn_text, last, recv, recv_node, pos, pos_nodes, kw, kw_nodes, extra)
        self._check_sinks(call)
        result = self._call_result(call, st)
        self._call_effects(call, st)
        return result

    def _is_weak_random(self, c: _Call) -> bool:
        if c.fn.startswith("random.") and c.fn.count(".") == 1 and c.last in WEAK_RANDOM_FUNCS:
            return True
        if c.recv_node is None and c.fn in self._random_names:
            return True
        return c.recv is not None and "weakrng" in c.recv.flags and c.last in WEAK_RANDOM_FUNCS

    def _specific_clean(self, c: _Call) -> frozenset[str]:
        out: set[str] = set()
        low = c.last.lower()
        if "escape" in low or (c.last in _XSS_SANITIZER_NAMES and c.fn.startswith("bleach.")):
            out |= _XSS_CLEAN
        if c.last in ("quoteattr", "strip_tags", "sanitize_html"):
            out |= _XSS_CLEAN
        if c.last in _SQL_ESCAPES:
            out.add(CWE_SQL)
        if c.last in _LDAP_ESCAPES:
            out.add(CWE_LDAP)
        if c.last == "replace" and c.recv is not None and c.pos:
            old = c.pos[0].const
            new = c.pos[1].const if len(c.pos) > 1 else ""
            if isinstance(old, str) and old in _QUOTES and isinstance(new, str) and old not in new:
                out.add(CWE_XPATH)
        if self._ctx is not None:
            out |= {cwe for cwe in self._cwes if self._ctx.clears(c.fn, frozenset({cwe}))}
        return frozenset(out)

    def _call_result(self, c: _Call, st: State) -> Val:
        args = c.every_arg()
        static_recv = (
            c.recv_node is not None
            and self._compact(c.recv_node) in _REQUEST_PATH
            and bool(self._fn_stack)
            and self._fn_stack[-1].static_path
        )
        # Only a plain dotted target (``request.args.get``) is matched as text; a
        # receiver that is itself an expression was evaluated on its own above.
        dotted = c.recv_node is None or self._path(c.recv_node) is not None
        if dotted and (c.fn == "input" or self._is_source(c.fn)) and not static_recv:
            return TAINT
        if c.recv is not None and c.last in self.source_methods and "reqobj" in c.recv.flags:
            return TAINT
        if c.last in self.source_functions and (
            c.recv_node is None or (self._path(c.recv_node) or "") not in st.vars
        ):
            return TAINT
        if self._is_weak_random(c):
            return Val(weak=True)
        if c.fn.endswith("random.Random") or (
            c.recv_node is None and c.fn == "Random" and "Random" in self._random_names
        ):
            return Val(flags=frozenset({"weakrng"}))
        if c.last in UNIVERSAL_SANITIZERS or (
            self._ctx is not None and self._ctx.clears(c.fn, None)
        ):
            numeric = c.last in NUMERIC_SANITIZERS
            return Val(lit=numeric or all(a.lit for a in args), weak=any(a.weak for a in args))
        recv = c.recv
        if not args and c.last in _DICT_CTORS:
            return Val(lit=True, elems=())
        if not args and c.last in _LIST_CTORS:
            return Val(lit=True, seq=())
        if self._result_is_not_input(c):
            # A cursor, a process, a file handle or query results: what the
            # sink produced, not the attacker's text.
            return UNKNOWN
        if c.last in REDIRECT_FNS:
            v = combine(args)
            return replace(v, clean=v.clean | _XSS_CLEAN) if v.taint else v
        # Container reads.
        if recv is not None and c.last in ("get", "pop") and c.pos:
            if recv.elems is not None:
                keys = [c.pos[0]] if c.last == "pop" or len(c.pos) == 1 else c.pos[:2]
                found = self._lookup(recv, keys)
                if found is not None:
                    return found
                default = c.pos[1] if len(c.pos) > 1 and len(keys) == 1 else c.kw.get("fallback")
                return summary(default) if default is not None else UNKNOWN
            if recv.seq is not None and c.last == "pop":
                idx = c.pos[0].const
                if (
                    isinstance(idx, int)
                    and not isinstance(idx, bool)
                    and -len(recv.seq) <= idx < len(recv.seq)
                ):
                    return recv.seq[idx]
        if recv is not None and c.last == "pop" and not c.pos and recv.seq:
            return recv.seq[-1]
        if recv is not None and c.last == "copy" and not args:
            return recv
        if recv is not None and c.last in ("values", "items") and recv.elems is not None:
            return summary(recv)
        if recv is not None and c.last == "keys" and recv.elems is not None:
            return Val(lit=True)
        extra_clean = self._specific_clean(c)
        if c.last == "jsonify" or c.last == "render_template":
            v = combine(args)
            return replace(v, clean=v.clean | _XSS_CLEAN) if v.taint else v
        if c.last in ("make_response", "Response") and c.pos:
            body = c.pos[0]
            if body.seq:
                body = body.seq[0]
            return summary(body)
        flags: set[str] = set()
        if c.last in PATH_CTORS:
            flags.add("path")
        if (
            recv is not None
            and "path" in recv.flags
            and c.last
            in (
                "resolve",
                "absolute",
                "joinpath",
                "with_name",
                "with_suffix",
                "expanduser",
            )
        ):
            flags.add("path")
            if c.last in ("resolve", "absolute"):
                flags.add("normalized")
        if c.fn in NORMALIZERS:
            flags.add("normalized")
        if c.last in ("urlparse", "urlsplit") and c.pos_nodes:
            p = self._path(c.pos_nodes[0])
            if p is not None:
                flags.add("urlof:" + p)
        if any(n.type == "identifier" and self.text(n) == "request" for n in c.pos_nodes) or any(
            n is not None and n.type == "identifier" and self.text(n) == "request"
            for n in c.kw_nodes.values()
        ):
            flags.add("reqobj")
        if c.last == "XMLParser" and (
            self._kw_text(c, "resolve_entities") == "True"
            or self._kw_text(c, "no_network") == "False"
        ):
            flags.add("xxe")
        parts = ([recv] if recv is not None else []) + args
        v = combine(parts)
        pure = (c.recv_node is None and c.last in PURE_FUNCTIONS) or (
            c.recv_node is not None and (c.last in PURE_METHODS or c.last in PURE_FUNCTIONS)
        )
        # ``base64.b64decode(x)``: a module (an untracked dotted name) is a
        # namespace, not a value, so it does not make the result non-literal.
        recv_path = self._path(c.recv_node) if c.recv_node is not None else None
        namespace = (
            recv is not None
            and not recv.taint
            and recv_path is not None
            and recv_path.split(".", 1)[0] not in st.vars
        )
        recv_lit = recv is None or recv.lit or (namespace and c.last in PURE_FUNCTIONS)
        lit = pure and recv_lit and all(a.lit for a in args)
        if c.last == "format" and recv is not None and not v.lit:
            flags.add("dyn")
        const: Any = NOCONST
        if (
            c.fn == "str"
            and len(c.pos) == 1
            and isinstance(c.pos[0].const, (str, int, float, bool))
        ):
            const = str(c.pos[0].const)
        clean = v.clean | extra_clean if v.taint else frozenset()
        return Val(
            taint=v.taint,
            clean=clean,
            lit=lit,
            weak=v.weak,
            param=v.param,
            flags=frozenset(flags),
            const=const,
        )

    def _result_is_not_input(self, c: _Call) -> bool:
        if SQL_FN.search(c.fn) or CMD_FN.search(c.fn) or PATH_FN.search(c.fn):
            return True
        if c.recv is not None and "path" in c.recv.flags and c.last in PATH_METHODS:
            return c.last not in ("resolve", "absolute")
        if self._ldap and c.last in LDAP_SEARCH:
            return True
        return c.last in ("xpath", "XPath") or c.fn in (
            "elementpath.select",
            "elementpath.iter_select",
        )

    def _kw_text(self, c: _Call, name: str) -> str | None:
        node = c.kw_nodes.get(name)
        return self.text(node) if node is not None else None

    @staticmethod
    def _lookup(recv: Val, keys: list[Val]) -> Val | None:
        assert recv.elems is not None
        consts = [k.const for k in keys]
        if any(k is NOCONST for k in consts):
            return None
        wanted: list[Any] = []
        if len(consts) == 2:
            wanted.append(tuple(consts))
        wanted.append(consts[0])
        for w in wanted:
            for k, v in recv.elems:
                if _same_const(k, w):
                    return v
        return None

    def _call_effects(self, c: _Call, st: State) -> None:
        if c.recv_node is None:
            return
        path = self._path(c.recv_node)
        if path is None:
            return
        last = c.last
        if last == "setFeature" and len(c.pos_nodes) >= 2:
            feature = self.text(c.pos_nodes[0])
            enabled = self.text(c.pos_nodes[1]) in ("True", "1")
            if enabled and _EXTERNAL_ENTITY_FEATURE.search(feature):
                cur = st.get(path)
                st.vars[path] = replace(cur, flags=cur.flags | {"xxe"})
            return
        if last not in _MUTATORS:
            return
        known = st.vars.get(path)
        if known is None and not any(a.taint or a.weak for a in c.every_arg()):
            return  # e.g. a module-level list we know nothing about
        st.vars[path] = self._mutate(known if known is not None else UNKNOWN, c)

    def _mutate(self, cur: Val, c: _Call) -> Val:
        last, pos = c.last, c.pos
        if cur.seq is not None:
            seq = list(cur.seq)
            if last == "append" and len(pos) == 1:
                return self._seq_val([*seq, pos[0]], cur.flags)
            if last == "insert" and len(pos) == 2 and isinstance(pos[0].const, int):
                seq.insert(pos[0].const, pos[1])
                return self._seq_val(seq, cur.flags)
            if last == "extend" and len(pos) == 1 and pos[0].seq is not None:
                return self._seq_val([*seq, *pos[0].seq], cur.flags)
            if last == "pop":
                idx = pos[0].const if pos else -1
                if (
                    isinstance(idx, int)
                    and not isinstance(idx, bool)
                    and -len(seq) <= idx < len(seq)
                ):
                    del seq[idx]
                    return self._seq_val(seq, cur.flags)
            if last == "clear":
                return self._seq_val([], cur.flags)
        if cur.elems is not None:
            items = dict(cur.elems)
            if last == "set" and len(pos) in (2, 3):
                keys = pos[:-1]
                if all(self._hashable_const(k) for k in keys):
                    key = keys[0].const if len(keys) == 1 else (keys[0].const, keys[1].const)
                    items[key] = pos[-1]
                    return self._dict_val(items, cur.flags)
            if last == "pop" and pos and self._hashable_const(pos[0]):
                items.pop(pos[0].const, None)
                return self._dict_val(items, cur.flags)
            if last == "setdefault" and pos and self._hashable_const(pos[0]):
                if pos[0].const not in items:
                    items[pos[0].const] = pos[1] if len(pos) > 1 else Val(lit=True, const=None)
                return self._dict_val(items, cur.flags)
            if last == "update" and len(pos) == 1 and pos[0].elems is not None and not c.kw:
                items.update(dict(pos[0].elems))
                return self._dict_val(items, cur.flags)
            if last == "clear":
                return self._dict_val({}, cur.flags)
        if last in ("pop", "popleft", "remove", "discard", "sort", "reverse", "clear"):
            return replace(summary(cur), flags=cur.flags)
        merged = combine([summary(cur), *(summary(a) for a in c.every_arg())])
        return replace(merged, flags=cur.flags)

    # --- sinks --------------------------------------------------------------
    def _check_sinks(self, c: _Call) -> None:
        fn, last = c.fn, c.last
        if SQL_FN.search(fn):
            q = c.arg(0, "sql", "query", "operation", "statement")
            if q is not None:
                if q.tainted_for(SINK_CWES["ast-sql-injection"]):
                    self._emit("ast-sql-injection", c.node)
                elif q.param and not q.lit and "dyn" in q.flags:
                    self._emit("ast-sql-string-building", c.node)
        if CMD_FN.search(fn):
            if fn.startswith(("os.exec", "os.spawn")):
                vals = [*c.pos, *c.extra]
            else:
                first = c.arg(0, "args", "cmd", "command")
                vals = ([first] if first is not None else []) + c.extra
            if any(v.tainted_for(SINK_CWES["ast-command-injection"]) for v in vals):
                self._emit("ast-command-injection", c.node)
            if fn in ("os.system", "os.popen") or (
                SHELL_CMD_FN.search(fn) and self._kw_text(c, "shell") not in (None, "False")
            ):
                self._verdict("shell", c.node, vals[0] if vals else None)
        if PATH_FN.search(fn):
            vals = c.pos[:2] + [
                c.kw[k] for k in ("file", "filename", "path", "name", "src", "dst") if k in c.kw
            ]
            if any(v.tainted_for(SINK_CWES["ast-path-traversal"]) for v in vals):
                self._emit("ast-path-traversal", c.node)
        if (
            c.recv is not None
            and "path" in c.recv.flags
            and last in PATH_METHODS
            and c.recv.tainted_for(SINK_CWES["ast-path-traversal"])
        ):
            self._emit("ast-path-traversal", c.node)
        if CODE_FN.search(fn):
            v = c.arg(0, "source", "object")
            if v is not None and v.tainted_for(SINK_CWES["ast-code-injection"]):
                self._emit("ast-code-injection", c.node)
            elif v is not None and v.param and not v.lit and fn != "compile":
                # compile() alone is often a syntax check; eval/exec run the text.
                self._emit("ast-eval-of-parameter", c.node)
        if DESER_FN.search(fn) or (YAML_LOAD_FN.search(fn) and self._yaml_unsafe(c)):
            v = c.arg(0, "data", "stream", "file", "s")
            self._verdict("deser", c.node, v)
            if v is not None and v.tainted_for(SINK_CWES["ast-unsafe-deserialization"]):
                self._emit("ast-unsafe-deserialization", c.node)
        self._check_ldap(c)
        self._check_xpath(c)
        if last in XML_PARSE and c.pos:
            data = c.pos[0]
            others = c.pos[1:] + list(c.kw.values())
            enabled = any("xxe" in o.flags for o in others) or (
                c.recv is not None and "xxe" in c.recv.flags
            )
            if enabled and data.tainted_for(SINK_CWES["ast-xxe"]):
                self._emit("ast-xxe", c.node)
        if last in REDIRECT_FNS:
            v = c.arg(0, "location", "url", "redirect_to", "to")
            if v is not None and v.tainted_for(SINK_CWES["ast-open-redirect"]):
                self._emit("ast-open-redirect", c.node)
        if last in MARKUP_FNS and c.pos and c.pos[0].tainted_for(SINK_CWES["ast-xss"]):
            self._emit("ast-xss", c.node)
        if last in DJANGO_RESPONSES and c.pos and c.pos[0].tainted_for(SINK_CWES["ast-xss"]):
            ctype = self._kw_text(c, "content_type")
            if ctype is None or "html" in ctype:
                self._emit("ast-xss", c.node)
        if (
            last in ("update", "setdefault")
            and c.recv_node is not None
            and SESSION_RE.search(self._compact(c.recv_node))
            and any(v.tainted_for(SINK_CWES["ast-trust-boundary"]) for v in c.every_arg())
        ):
            self._emit("ast-trust-boundary", c.node)
        if any(v.weak for v in c.every_arg()) and (
            last == "set_cookie"
            or SENSITIVE_RE.search(last)
            or any(SENSITIVE_RE.search(k) and v.weak for k, v in c.kw.items())
        ):
            self._emit("ast-weak-random", c.node)

    def _check_xpath(self, c: _Call) -> None:
        last, fn = c.last, c.fn
        v: Val | None = None
        if last in ("xpath", "XPath") or fn.endswith("etree.XPath"):
            v = c.arg(0, "_path", "path")
        elif fn in ("elementpath.select", "elementpath.iter_select"):
            v = c.arg(1, "path")
        elif fn == "elementpath.Selector" or (
            self._xml
            and last in ("find", "findall", "iterfind", "findtext")
            and c.recv_node is not None
            and self.text(c.recv_node) not in ("re", "regex")
        ):
            v = c.arg(0, "path")
        if v is not None and v.tainted_for(SINK_CWES["ast-xpath-injection"]):
            self._emit("ast-xpath-injection", c.node)

    def _check_ldap(self, c: _Call) -> None:
        """ldap3 ``conn.search(base, filter)`` / python-ldap ``search_s(base, scope, filter)``."""
        if not self._ldap or c.last not in LDAP_SEARCH or c.recv_node is None:
            return
        if self.text(c.recv_node) in ("re", "regex"):
            return
        if c.last == "search":
            vals = c.pos[:2] + [c.kw[k] for k in ("search_base", "search_filter") if k in c.kw]
        else:
            vals = [c.pos[i] for i in (0, 2) if i < len(c.pos)]
            vals += [c.kw[k] for k in ("base", "filterstr") if k in c.kw]
        if any(v.tainted_for(SINK_CWES["ast-ldap-injection"]) for v in vals):
            self._emit("ast-ldap-injection", c.node)

    def _yaml_unsafe(self, c: _Call) -> bool:
        loader = self._kw_text(c, "Loader")
        if loader is None and len(c.pos_nodes) > 1:
            loader = self.text(c.pos_nodes[1])
        if loader is None:
            return True  # PyYAML < 6 defaults to an unsafe loader; 6+ raises
        return not re.search(r"Safe|BaseLoader", loader)

    # --- conservative fallback ----------------------------------------------
    def _flat(self, node, st: State) -> Val:
        """Taint of ``node`` from a flat scan, also checking simple sinks inside.

        Used past the nesting limits instead of recursing: any source or tainted
        variable anywhere in the subtree taints the whole of it.
        """
        taint = self._is_source(self.text(node))
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "identifier":
                v = st.vars.get(self.text(n))
                if v is not None and v.taint:
                    taint = True
            elif n.type == "call":
                self._flat_call(n, st)
            stack.extend(n.children)
        return Val(taint=taint)

    def _flat_call(self, node, st: State) -> None:
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            return
        fn_text = self._compact(fn)
        if SQL_FN.search(fn_text):
            sink = "ast-sql-injection"
        elif CMD_FN.search(fn_text):
            sink = "ast-command-injection"
        elif PATH_FN.search(fn_text):
            sink = "ast-path-traversal"
        elif CODE_FN.search(fn_text):
            sink = "ast-code-injection"
        elif DESER_FN.search(fn_text):
            sink = "ast-unsafe-deserialization"
        else:
            return
        named = [a for a in args.named_children if a.type != "comment"]
        if sink == "ast-sql-injection":
            named = named[:1]
        for a in named:
            if self._is_source(self.text(a)) or self._flat_ident_taint(a, st):
                self._emit(sink, node)
                return

    def _flat_ident_taint(self, node, st: State) -> bool:
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "identifier":
                v = st.vars.get(self.text(n))
                if v is not None and v.taint:
                    return True
            stack.extend(n.children)
        return False


def iter_functions(root) -> Iterable[tuple[Any, bool]]:
    """Every function definition under ``root`` with whether it is a method."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            parent = node.parent
            if parent is not None and parent.type == "decorated_definition":
                parent = parent.parent
            is_method = (
                parent is not None
                and parent.type == "block"
                and parent.parent is not None
                and parent.parent.type == "class_definition"
            )
            yield node, is_method
        stack.extend(reversed(node.children))


def source_callables(
    src: bytes, root, context: LanguageContext | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Methods and functions in ``root`` that return untrusted input.

    Returns ``(methods, functions)``, each mapping a name to its definition
    node. A method qualifies when one of its ``return`` values is tainted with
    nothing seeded (for example ``return self.request.form.get(name)``): calls
    to it on an object built from the request then count as sources.
    """
    methods: dict[str, Any] = {}
    functions: dict[str, Any] = {}
    flow = Flow(src, None, context=context)
    for fn, is_method in iter_functions(root):
        name_node = fn.child_by_field_name("name")
        if name_node is None:
            continue
        name = flow.text(name_node)
        parent = fn.parent
        if parent is not None and parent.type == "decorated_definition":
            decorators = [flow.text(c) for c in parent.named_children if c.type == "decorator"]
            if any(ROUTE_DECORATOR.search(d) or METHOD_DECORATOR.search(d) for d in decorators):
                continue  # a view returns a response, it is not a helper
        if flow.function_returns_taint(fn):
            (methods if is_method else functions)[name] = fn
    return methods, functions
