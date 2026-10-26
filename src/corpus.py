"""A fixture application with hand-verified reachability ground truth.

The ground truth is the whole asset. Without it, "we cut the findings list"
is a number with no error bars, and the one thing the tool must never do - hide
a reachable vulnerability - is unmeasurable.
"""

from __future__ import annotations

from .verdict import Advisory

SOURCES: dict[str, str] = {
    "app.main": """
import app.handlers
import app.reports

def main():
    app.handlers.handle_upload()
    app.handlers.handle_login()

def cli_entry():
    app.reports.render_monthly()
""",
    "app.handlers": """
import yamllib
import imagelib
import app.util

def handle_upload():
    data = app.util.read_body()
    return imagelib.decode_png(data)

def handle_login():
    return app.util.check_password('x', 'y')

def unused_admin_import():
    # Never called from any entry point.
    return yamllib.unsafe_load('{}')
""",
    "app.reports": """
import templating
import app.util

def render_monthly():
    return templating.render('monthly', app.util.fetch_rows())
""",
    "app.util": """
import hashlib

def read_body():
    return b''

def fetch_rows():
    return []

def check_password(a, b):
    return hashlib.sha256(a.encode()).hexdigest() == b
""",
    # Third-party packages, modelled as modules so their functions are nodes.
    "yamllib": """
def unsafe_load(s):
    return _construct(s)

def safe_load(s):
    return {}

def _construct(s):
    return {}
""",
    "imagelib": """
def decode_png(b):
    return _parse_chunk(b)

def decode_gif(b):
    return _parse_chunk(b)

def _parse_chunk(b):
    return None
""",
    "templating": """
def render(name, rows):
    return _expand(name)

def _expand(name):
    return ''

def render_unsafe(s):
    return s
""",
    "cryptolib": """
def sign(msg):
    return b''

def verify(msg, sig):
    return True
""",
}

ENTRY_POINTS = ["app.main.main", "app.main.cli_entry"]

ADVISORIES: list[Advisory] = [
    Advisory("OSV-2026-0001", "imagelib", "imagelib.decode_png",
             "heap overflow in PNG chunk parsing", "critical"),
    Advisory("OSV-2026-0002", "imagelib", "imagelib.decode_gif",
             "integer overflow in GIF decoder", "high"),
    Advisory("OSV-2026-0003", "yamllib", "yamllib.unsafe_load",
             "arbitrary object construction", "critical"),
    Advisory("OSV-2026-0004", "yamllib", "yamllib.safe_load",
             "denial of service on deeply nested input", "medium"),
    Advisory("OSV-2026-0005", "templating", "templating.render",
             "template injection via name", "high"),
    Advisory("OSV-2026-0006", "templating", "templating.render_unsafe",
             "server-side template injection", "critical"),
    Advisory("OSV-2026-0007", "cryptolib", "cryptolib.verify",
             "signature bypass", "critical"),
    Advisory("OSV-2026-0008", "imagelib", None,
             "unspecified issue affecting all of imagelib", "high"),
]

#: GROUND TRUTH, established by reading the fixture by hand.
#: Verified against a graph with NO dynamic dispatch (see SOURCES above).
EXPECTED: dict[str, str] = {
    "OSV-2026-0001": "reachable",       # main -> handle_upload -> decode_png
    "OSV-2026-0002": "not-reachable",   # decode_gif is never called
    "OSV-2026-0003": "not-reachable",   # unused_admin_import is never called
    "OSV-2026-0004": "not-reachable",
    "OSV-2026-0005": "reachable",       # cli_entry -> render_monthly -> render
    "OSV-2026-0006": "not-reachable",
    "OSV-2026-0007": "not-reachable",   # cryptolib is never imported
    "OSV-2026-0008": "indeterminate",   # no symbol named
}

#: The same application, with one dynamic dispatch added. Everything that was
#: NOT_REACHABLE must degrade to INDETERMINATE - never stay "safe".
SOURCES_WITH_DYNAMIC = {
    **SOURCES,
    "app.handlers": SOURCES["app.handlers"].replace(
        "def handle_login():\n    return app.util.check_password('x', 'y')",
        "def handle_login():\n"
        "    fn = getattr(app.util, 'check_password')\n"
        "    return fn('x', 'y')",
    ),
}
