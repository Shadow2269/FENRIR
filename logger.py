"""
logger.py
Structured logger with severity levels and optional rich-color output.
"""
import datetime

try:
    from rich import print as rprint
    from rich.markup import escape
    _RICH = True
except ImportError:
    _RICH = False


def _fmt(level: str, msg: str) -> str:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    return f"[{ts}] [{level}] {msg}"


def log(msg: str):
    if _RICH:
        rprint(f"[dim]{_fmt('INFO', escape(msg))}[/dim]")
    else:
        print(_fmt("INFO", msg))


def success(msg: str):
    if _RICH:
        rprint(f"[bold green]{_fmt('OK  ', escape(msg))}[/bold green]")
    else:
        print(_fmt("OK  ", msg))


def warn(msg: str):
    if _RICH:
        rprint(f"[bold yellow]{_fmt('WARN', escape(msg))}[/bold yellow]")
    else:
        print(_fmt("WARN", msg))


def error(msg: str):
    if _RICH:
        rprint(f"[bold red]{_fmt('ERR ', escape(msg))}[/bold red]")
    else:
        print(_fmt("ERR ", msg))
