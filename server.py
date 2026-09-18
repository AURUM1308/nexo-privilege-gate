from __future__ import annotations

from http.cookies import SimpleCookie
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path
from urllib.parse import (
    parse_qs,
    urlparse,
)

import json
import secrets
import threading
import time
import uuid


from nexo.audit import AuditLog
from nexo.policy import evaluate
from nexo.sandbox import SandboxFS


# ============================================================
# NEXO PRIVILEGE GATE v0.4
# Local enforcement server
# ============================================================


HOST = "127.0.0.1"
PORT = 8765

MAX_BODY_BYTES = 512_000

PENDING_TTL_SECONDS = 600

CONTROL_COOKIE_NAME = "nexo_control"

CONTROL_SESSION_SECONDS = 8 * 60 * 60


ROOT = (
    Path(__file__)
    .resolve()
    .parent
)

STATIC_DIR = (
    ROOT
    / "static"
)

SANDBOX_DIR = (
    ROOT
    / "sandbox_data"
)

STATE_DIR = (
    ROOT
    / ".nexo_state"
)


# ============================================================
# FILESYSTEM
# ============================================================


filesystem = SandboxFS(
    SANDBOX_DIR
)

filesystem.seed()


# ============================================================
# AUDIT
# ============================================================


audit = AuditLog(
    STATE_DIR
)


# ============================================================
# AUTHENTICATION / AUTHORIZATION
# ============================================================


STATE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


AGENT_TOKEN_PATH = (
    STATE_DIR
    / "agent.token"
)


def load_or_create_agent_token() -> str:

    if AGENT_TOKEN_PATH.exists():

        token = (
            AGENT_TOKEN_PATH
            .read_text(
                encoding="utf-8"
            )
            .strip()
        )

        if token:
            return token


    token = secrets.token_urlsafe(
        48
    )


    AGENT_TOKEN_PATH.write_text(
        token,
        encoding="utf-8",
    )


    return token


AGENT_TOKEN = (
    load_or_create_agent_token()
)


# Human control authentication is intentionally ephemeral.
#
# It is NOT written to disk.
#
# The user receives a one-time bootstrap URL in the terminal.
# Opening that URL creates an HttpOnly browser session.

CONTROL_SESSION_TOKEN = (
    secrets.token_urlsafe(
        48
    )
)

CONTROL_BOOTSTRAP_TOKEN = (
    secrets.token_urlsafe(
        32
    )
)


# ============================================================
# PENDING HUMAN APPROVALS
# ============================================================


PENDING: dict[
    str,
    dict,
] = {}


PENDING_LOCK = (
    threading.Lock()
)


# ============================================================
# UTILITIES
# ============================================================


def now_iso() -> str:

    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(),
    )


def clean_expired_pending() -> None:

    current = time.time()

    expired = []


    with PENDING_LOCK:

        for request_id, item in (
            PENDING.items()
        ):

            if (
                current
                - item["created"]
                > PENDING_TTL_SECONDS
            ):

                expired.append(
                    request_id
                )


        for request_id in expired:

            PENDING.pop(
                request_id,
                None,
            )


    for request_id in expired:

        audit.append(
            {
                "timestamp":
                    now_iso(),

                "event":
                    "approval_expired",

                "request_id":
                    request_id,
            }
        )


# ============================================================
# REAL TOOL EXECUTION
# ============================================================


def execute_operation(
    payload: dict,
) -> dict:

    operation = payload[
        "operation"
    ]

    path = payload.get(
        "path",
        "",
    )


    if operation == "list":

        return {
            "entries":
                filesystem.list_dir(
                    path
                )
        }


    if operation == "read":

        return filesystem.read_text(
            path
        )


    if operation == "write":

        return filesystem.write_text(
            path,
            payload.get(
                "content",
                "",
            ),
        )


    if operation == "mkdir":

        return filesystem.mkdir(
            path
        )


    if operation == "delete":

        return filesystem.quarantine(
            path
        )


    raise ValueError(
        "Unsupported operation."
    )


# ============================================================
# HTTP SERVER
# ============================================================


class NEXOHandler(
    BaseHTTPRequestHandler
):

    server_version = (
        "NEXOPrivilegeGate/0.4"
    )


    # --------------------------------------------------------
    # LOGGING
    # --------------------------------------------------------

    def log_message(
        self,
        fmt: str,
        *args,
    ) -> None:

        print(
            (
                f"[{self.log_date_time_string()}] "
                f"{self.client_address[0]} "
                f"{fmt % args}"
            )
        )


    # --------------------------------------------------------
    # SECURITY HEADERS
    # --------------------------------------------------------

    def end_headers(
        self,
    ) -> None:

        self.send_header(
            "X-Content-Type-Options",
            "nosniff",
        )

        self.send_header(
            "X-Frame-Options",
            "DENY",
        )

        self.send_header(
            "Referrer-Policy",
            "no-referrer",
        )

        self.send_header(
            "Cache-Control",
            "no-store",
        )

        self.send_header(
            "Permissions-Policy",
            (
                "camera=(), "
                "microphone=(), "
                "geolocation=()"
            ),
        )

        self.send_header(
            "Content-Security-Policy",
            (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'none'; "
                "frame-ancestors 'none'"
            ),
        )

        super().end_headers()


    # --------------------------------------------------------
    # REQUEST SECURITY
    # --------------------------------------------------------

    def _host_ok(
        self,
    ) -> bool:

        host = (
            self.headers
            .get(
                "Host",
                "",
            )
            .lower()
        )


        return host in {
            f"127.0.0.1:{PORT}",
            f"localhost:{PORT}",
        }


    def _origin_ok(
        self,
    ) -> bool:

        origin = (
            self.headers
            .get(
                "Origin"
            )
        )


        # API clients such as an MCP connector may not send Origin.
        if not origin:
            return True


        return origin in {
            f"http://127.0.0.1:{PORT}",
            f"http://localhost:{PORT}",
        }


    def _security_precheck(
        self,
    ) -> bool:

        if not self._host_ok():

            self._send_json(
                403,
                {
                    "ok":
                        False,

                    "error":
                        "Invalid Host header.",
                },
            )

            return False


        if not self._origin_ok():

            self._send_json(
                403,
                {
                    "ok":
                        False,

                    "error":
                        (
                            "Cross-origin request "
                            "was rejected."
                        ),
                },
            )

            return False


        return True


    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    def _send_json(
        self,
        status: int,
        body: dict,
    ) -> None:

        data = json.dumps(
            body,
            ensure_ascii=False,
        ).encode(
            "utf-8"
        )


        self.send_response(
            status
        )

        self.send_header(
            "Content-Type",
            (
                "application/json; "
                "charset=utf-8"
            ),
        )

        self.send_header(
            "Content-Length",
            str(len(data)),
        )

        self.end_headers()


        self.wfile.write(
            data
        )


    def _read_json(
        self,
    ) -> dict:

        content_type = (
            self.headers
            .get(
                "Content-Type",
                "",
            )
            .split(
                ";",
                1,
            )[0]
            .strip()
            .lower()
        )


        if (
            content_type
            != "application/json"
        ):

            raise ValueError(
                (
                    "Content-Type must be "
                    "application/json."
                )
            )


        try:

            length = int(
                self.headers
                .get(
                    "Content-Length",
                    "0",
                )
            )

        except ValueError as exc:

            raise ValueError(
                "Invalid Content-Length."
            ) from exc


        if length <= 0:

            raise ValueError(
                "Request body is empty."
            )


        if (
            length
            > MAX_BODY_BYTES
        ):

            raise ValueError(
                (
                    "Request body exceeds "
                    "the configured limit."
                )
            )


        raw = self.rfile.read(
            length
        )


        try:

            decoded = raw.decode(
                "utf-8"
            )

            data = json.loads(
                decoded
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:

            raise ValueError(
                "Invalid JSON body."
            ) from exc


        if not isinstance(
            data,
            dict,
        ):

            raise ValueError(
                (
                    "JSON body must "
                    "be an object."
                )
            )


        return data


    # --------------------------------------------------------
    # CONTROL SESSION
    # --------------------------------------------------------

    def _get_cookie(
        self,
        name: str,
    ) -> str:

        raw_cookie = (
            self.headers
            .get(
                "Cookie",
                "",
            )
        )


        if not raw_cookie:
            return ""


        cookie = SimpleCookie()


        try:

            cookie.load(
                raw_cookie
            )

        except Exception:
            return ""


        morsel = cookie.get(
            name
        )


        if morsel is None:
            return ""


        return morsel.value


    def _control_authorized(
        self,
    ) -> bool:

        supplied = self._get_cookie(
            CONTROL_COOKIE_NAME
        )


        if not supplied:
            return False


        return secrets.compare_digest(
            supplied,
            CONTROL_SESSION_TOKEN,
        )


    def _agent_authorized(
        self,
    ) -> bool:

        supplied = (
            self.headers
            .get(
                "X-NEXO-Agent-Token",
                "",
            )
        )


        if not supplied:
            return False


        return secrets.compare_digest(
            supplied,
            AGENT_TOKEN,
        )


    # --------------------------------------------------------
    # BASIC HTML RESPONSES
    # --------------------------------------------------------

    def _send_control_required(
        self,
    ) -> None:

        html = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NEXO Privilege Gate</title>
<style>
body {
    background:#071019;
    color:#eef6ff;
    font-family:system-ui,sans-serif;
    max-width:760px;
    margin:80px auto;
    padding:24px;
}
.panel {
    border:1px solid #26394d;
    background:#0e1722;
    padding:28px;
    border-radius:16px;
}
h1 { margin-top:0; }
p {
    color:#9fb0c3;
    line-height:1.6;
}
code {
    color:#3ddc97;
}
</style>
</head>
<body>
<div class="panel">
<h1>⛨ NEXO Privilege Gate</h1>
<p>
This browser does not currently have a valid
human-control session.
</p>
<p>
Return to the terminal where NEXO was started and
open the <code>Human control URL</code> printed there.
</p>
</div>
</body>
</html>
"""

        data = html.encode(
            "utf-8"
        )


        self.send_response(
            401
        )

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )

        self.send_header(
            "Content-Length",
            str(len(data)),
        )

        self.end_headers()


        self.wfile.write(
            data
        )


    # ========================================================
    # GET
    # ========================================================

    def do_GET(
        self,
    ) -> None:

        if not self._security_precheck():
            return


        clean_expired_pending()


        parsed = urlparse(
            self.path
        )


        path = parsed.path

        query = parse_qs(
            parsed.query
        )


        # ----------------------------------------------------
        # HUMAN CONTROL BOOTSTRAP
        # ----------------------------------------------------

        if path == "/":

            supplied_setup = (
                query.get(
                    "setup",
                    [""],
                )[0]
            )


            if (
                supplied_setup
                and secrets.compare_digest(
                    supplied_setup,
                    CONTROL_BOOTSTRAP_TOKEN,
                )
            ):

                self.send_response(
                    303
                )

                self.send_header(
                    "Location",
                    "/",
                )

                self.send_header(
                    "Set-Cookie",
                    (
                        f"{CONTROL_COOKIE_NAME}="
                        f"{CONTROL_SESSION_TOKEN}; "
                        "HttpOnly; "
                        "SameSite=Strict; "
                        "Path=/; "
                        f"Max-Age={CONTROL_SESSION_SECONDS}"
                    ),
                )

                self.end_headers()

                return


            if not self._control_authorized():

                self._send_control_required()

                return


            index_path = (
                STATIC_DIR
                / "index.html"
            )


            if not index_path.exists():

                self._send_json(
                    503,
                    {
                        "ok":
                            False,

                        "error":
                            (
                                "Local dashboard "
                                "static/index.html "
                                "has not been created yet."
                            ),
                    },
                )

                return


            data = (
                index_path
                .read_bytes()
            )


            self.send_response(
                200
            )

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8",
            )

            self.send_header(
                "Content-Length",
                str(len(data)),
            )

            self.end_headers()


            self.wfile.write(
                data
            )

            return


        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        if path == "/api/status":

            if not self._control_authorized():

                self._send_json(
                    401,
                    {
                        "ok":
                            False,

                        "error":
                            (
                                "Human control "
                                "authorization required."
                            ),
                    },
                )

                return


            valid, count, message = (
                audit.verify()
            )


            with PENDING_LOCK:

                pending_count = len(
                    PENDING
                )


            self._send_json(
                200,
                {
                    "ok":
                        True,

                    "version":
                        "0.4.0-local",

                    "sandbox_root":
                        str(
                            SANDBOX_DIR
                        ),

                    "audit_valid":
                        valid,

                    "audit_records":
                        count,

                    "audit_message":
                        message,

                    "pending_requests":
                        pending_count,
                },
            )

            return


        # ----------------------------------------------------
        # AUDIT
        # ----------------------------------------------------

        if path == "/api/audit":

            if not self._control_authorized():

                self._send_json(
                    401,
                    {
                        "ok":
                            False,

                        "error":
                            "Unauthorized.",
                    },
                )

                return


            self._send_json(
                200,
                {
                    "ok":
                        True,

                    "entries":
                        audit.latest(
                            100
                        ),
                },
            )

            return


        # ----------------------------------------------------
        # PENDING REQUESTS
        # ----------------------------------------------------

        if path == "/api/pending":

            if not self._control_authorized():

                self._send_json(
                    401,
                    {
                        "ok":
                            False,

                        "error":
                            "Unauthorized.",
                    },
                )

                return


            with PENDING_LOCK:

                items = [

                    {
                        "request_id":
                            request_id,

                        "created":
                            item["created"],

                        "payload":
                            item["payload"],

                        "evaluation":
                            item["evaluation"],
                    }

                    for request_id, item
                    in PENDING.items()
                ]


            self._send_json(
                200,
                {
                    "ok":
                        True,

                    "requests":
                        items,
                },
            )

            return


        self._send_json(
            404,
            {
                "ok":
                    False,

                "error":
                    "Not found.",
            },
        )


    # ========================================================
    # POST
    # ========================================================

    def do_POST(
        self,
    ) -> None:

        if not self._security_precheck():
            return


        clean_expired_pending()


        path = urlparse(
            self.path
        ).path


        try:

            payload = (
                self._read_json()
            )

        except Exception as exc:

            self._send_json(
                400,
                {
                    "ok":
                        False,

                    "error":
                        str(exc),
                },
            )

            return


        # ----------------------------------------------------
        # REAL AGENT REQUEST
        # ----------------------------------------------------

        if path == "/api/action":

            if not self._agent_authorized():

                self._send_json(
                    401,
                    {
                        "ok":
                            False,

                        "error":
                            (
                                "Invalid or missing "
                                "agent token."
                            ),
                    },
                )

                return


            self._handle_action(
                payload,
                source="agent",
            )

            return


        # ----------------------------------------------------
        # CONTROL-UI DEMO REQUEST
        # ----------------------------------------------------

        if path == "/api/demo-action":

            if not self._control_authorized():

                self._send_json(
                    401,
                    {
                        "ok":
                            False,

                        "error":
                            (
                                "Human control "
                                "authorization required."
                            ),
                    },
                )

                return


            self._handle_action(
                payload,
                source="human-demo",
            )

            return


        # ----------------------------------------------------
        # APPROVE
        # ----------------------------------------------------

        if path == "/api/approve":

            if not self._control_authorized():

                self._send_json(
                    401,
                    {
                        "ok":
                            False,

                        "error":
                            (
                                "Human control "
                                "authorization required."
                            ),
                    },
                )

                return


            self._handle_approval(
                payload,
                approve=True,
            )

            return


        # ----------------------------------------------------
        # DENY
        # ----------------------------------------------------

        if path == "/api/deny":

            if not self._control_authorized():

                self._send_json(
                    401,
                    {
                        "ok":
                            False,

                        "error":
                            (
                                "Human control "
                                "authorization required."
                            ),
                    },
                )

                return


            self._handle_approval(
                payload,
                approve=False,
            )

            return


        # ----------------------------------------------------
        # VERIFY AUDIT
        # ----------------------------------------------------

        if path == "/api/audit/verify":

            if not self._control_authorized():

                self._send_json(
                    401,
                    {
                        "ok":
                            False,

                        "error":
                            "Unauthorized.",
                    },
                )

                return


            valid, count, message = (
                audit.verify()
            )


            self._send_json(
                200,
                {
                    "ok":
                        valid,

                    "records":
                        count,

                    "message":
                        message,
                },
            )

            return


        # ----------------------------------------------------
        # CLEAR AUDIT
        # ----------------------------------------------------

        if path == "/api/audit/clear":

            if not self._control_authorized():

                self._send_json(
                    401,
                    {
                        "ok":
                            False,

                        "error":
                            "Unauthorized.",
                    },
                )

                return


            audit.clear()


            self._send_json(
                200,
                {
                    "ok":
                        True,

                    "message":
                        "Local audit log cleared.",
                },
            )

            return


        self._send_json(
            404,
            {
                "ok":
                    False,

                "error":
                    "Not found.",
            },
        )


    # ========================================================
    # ACTION HANDLING
    # ========================================================

    def _handle_action(
        self,
        payload: dict,
        *,
        source: str,
    ) -> None:

        operation = str(
            payload.get(
                "operation",
                "",
            )
        ).lower().strip()


        path = str(
            payload.get(
                "path",
                "",
            )
        ).strip()


        content = str(
            payload.get(
                "content",
                "",
            )
        )


        path_ok = True
        path_reason = ""


        try:

            filesystem.resolve(
                path
            )

        except Exception as exc:

            path_ok = False

            path_reason = str(
                exc
            )


        evaluation = evaluate(
            operation,
            path,
            path_ok=path_ok,
            path_reason=path_reason,
            size_bytes=len(
                content.encode(
                    "utf-8"
                )
            ),
        )


        request_id = (
            uuid.uuid4().hex
        )


        audit.append(
            {
                "timestamp":
                    now_iso(),

                "event":
                    "policy_decision",

                "source":
                    source,

                "request_id":
                    request_id,

                "operation":
                    operation,

                "path":
                    path,

                "decision":
                    evaluation.decision,

                "risk":
                    evaluation.risk,

                "policy_id":
                    evaluation.policy_id,

                "reason":
                    evaluation.reason,
            }
        )


        # ----------------------------------------------------
        # DENY
        # ----------------------------------------------------

        if (
            evaluation.decision
            == "DENY"
        ):

            self._send_json(
                200,
                {
                    "ok":
                        True,

                    "request_id":
                        request_id,

                    "evaluation":
                        evaluation.to_dict(),

                    "executed":
                        False,

                    "pending_approval":
                        False,
                },
            )

            return


        action_payload = {

            "operation":
                operation,

            "path":
                path,

            "content":
                content,
        }


        # ----------------------------------------------------
        # HUMAN REVIEW
        # ----------------------------------------------------

        if (
            evaluation.decision
            == "REVIEW"
        ):

            with PENDING_LOCK:

                PENDING[
                    request_id
                ] = {

                    "created":
                        time.time(),

                    "payload":
                        action_payload,

                    "evaluation":
                        evaluation.to_dict(),

                    "source":
                        source,
                }


            self._send_json(
                200,
                {
                    "ok":
                        True,

                    "request_id":
                        request_id,

                    "evaluation":
                        evaluation.to_dict(),

                    "executed":
                        False,

                    "pending_approval":
                        True,
                },
            )

            return


        # ----------------------------------------------------
        # ALLOW → REAL EXECUTION
        # ----------------------------------------------------

        try:

            result = execute_operation(
                action_payload
            )


            audit.append(
                {
                    "timestamp":
                        now_iso(),

                    "event":
                        "execution",

                    "source":
                        source,

                    "request_id":
                        request_id,

                    "operation":
                        operation,

                    "path":
                        path,

                    "result":
                        "success",
                }
            )


            self._send_json(
                200,
                {
                    "ok":
                        True,

                    "request_id":
                        request_id,

                    "evaluation":
                        evaluation.to_dict(),

                    "executed":
                        True,

                    "pending_approval":
                        False,

                    "result":
                        result,
                },
            )


        except Exception as exc:

            audit.append(
                {
                    "timestamp":
                        now_iso(),

                    "event":
                        "execution_error",

                    "source":
                        source,

                    "request_id":
                        request_id,

                    "operation":
                        operation,

                    "path":
                        path,

                    "error":
                        str(exc),
                }
            )


            self._send_json(
                400,
                {
                    "ok":
                        False,

                    "request_id":
                        request_id,

                    "evaluation":
                        evaluation.to_dict(),

                    "executed":
                        False,

                    "error":
                        str(exc),
                },
            )


    # ========================================================
    # HUMAN APPROVAL
    # ========================================================

    def _handle_approval(
        self,
        payload: dict,
        *,
        approve: bool,
    ) -> None:

        request_id = str(
            payload.get(
                "request_id",
                "",
            )
        ).strip()


        if not request_id:

            self._send_json(
                400,
                {
                    "ok":
                        False,

                    "error":
                        "request_id is required.",
                },
            )

            return


        with PENDING_LOCK:

            pending = PENDING.pop(
                request_id,
                None,
            )


        if not pending:

            self._send_json(
                404,
                {
                    "ok":
                        False,

                    "error":
                        (
                            "Pending request not found, "
                            "expired, or already consumed."
                        ),
                },
            )

            return


        if (
            time.time()
            - pending["created"]
            > PENDING_TTL_SECONDS
        ):

            audit.append(
                {
                    "timestamp":
                        now_iso(),

                    "event":
                        "approval_expired",

                    "request_id":
                        request_id,
                }
            )


            self._send_json(
                410,
                {
                    "ok":
                        False,

                    "error":
                        "Approval request expired.",
                },
            )

            return


        action_payload = (
            pending[
                "payload"
            ]
        )


        # ----------------------------------------------------
        # HUMAN DENIAL
        # ----------------------------------------------------

        if not approve:

            audit.append(
                {
                    "timestamp":
                        now_iso(),

                    "event":
                        "human_denial",

                    "request_id":
                        request_id,

                    "operation":
                        action_payload[
                            "operation"
                        ],

                    "path":
                        action_payload[
                            "path"
                        ],
                }
            )


            self._send_json(
                200,
                {
                    "ok":
                        True,

                    "executed":
                        False,

                    "decision":
                        "DENY",
                },
            )

            return


        # ----------------------------------------------------
        # HUMAN APPROVAL → REAL EXECUTION
        # ----------------------------------------------------

        try:

            result = execute_operation(
                action_payload
            )


            audit.append(
                {
                    "timestamp":
                        now_iso(),

                    "event":
                        (
                            "human_approval_and_execution"
                        ),

                    "request_id":
                        request_id,

                    "operation":
                        action_payload[
                            "operation"
                        ],

                    "path":
                        action_payload[
                            "path"
                        ],

                    "result":
                        "success",
                }
            )


            self._send_json(
                200,
                {
                    "ok":
                        True,

                    "executed":
                        True,

                    "decision":
                        "APPROVED_ONCE",

                    "result":
                        result,
                },
            )


        except Exception as exc:

            audit.append(
                {
                    "timestamp":
                        now_iso(),

                    "event":
                        (
                            "human_approval_execution_error"
                        ),

                    "request_id":
                        request_id,

                    "operation":
                        action_payload[
                            "operation"
                        ],

                    "path":
                        action_payload[
                            "path"
                        ],

                    "error":
                        str(exc),
                }
            )


            self._send_json(
                400,
                {
                    "ok":
                        False,

                    "executed":
                        False,

                    "error":
                        str(exc),
                },
            )


# ============================================================
# STARTUP
# ============================================================


def main() -> None:

    control_url = (
        f"http://{HOST}:{PORT}/"
        f"?setup={CONTROL_BOOTSTRAP_TOKEN}"
    )


    print()
    print(
        "=============================================="
    )
    print(
        " NEXO Privilege Gate v0.4-local"
    )
    print(
        "=============================================="
    )
    print()

    print(
        f"Sandbox:\n{SANDBOX_DIR}"
    )

    print()

    print(
        "Human control URL:"
    )

    print(
        control_url
    )

    print()

    print(
        (
            "Open that URL in your browser. "
            "The setup token creates an HttpOnly "
            "local control session."
        )
    )

    print()

    print(
        "Agent API token file:"
    )

    print(
        AGENT_TOKEN_PATH
    )

    print()

    print(
        (
            "The server binds only to 127.0.0.1. "
            "Press Ctrl+C to stop."
        )
    )

    print()


    server = ThreadingHTTPServer(
        (
            HOST,
            PORT,
        ),
        NEXOHandler,
    )


    try:

        server.serve_forever()


    except KeyboardInterrupt:

        print()
        print(
            "Stopping NEXO Privilege Gate..."
        )


    finally:

        server.server_close()


if __name__ == "__main__":

    main()
