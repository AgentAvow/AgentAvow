"""SYNTHETIC known-bad fixture (never executed): CWE-78 command injection. A web
handler passes a query parameter into a shell=True argv list; the shell evaluates
`?src=x;id` as two commands. Untrusted input nearby keeps this critical."""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/thumb")
def thumb():
    src = request.args.get("src", "")
    subprocess.run(["convert", src, "/tmp/out.png"], shell=True, check=False)
    return "ok"
