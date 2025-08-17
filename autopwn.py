import argparse
import logging

from binary import Binary
from goals import find_goals
from vulns import find_vulns
from exploit import exploit, ExploitError, Remote, ExploitProgress
from tui import Autopwn

def main():
    parser = argparse.ArgumentParser(description="Find and exploit vulnerabilities in a binary")
    parser.add_argument("path", nargs=1)
    parser.add_argument("remote", nargs="?", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Print extra debug information")
    parser.add_argument("-i", "--interactive", action="store_true", help="Enable the pwn TUI")
    args = parser.parse_args()

    logging.getLogger("angr").setLevel(999)

    remote = None
    if args.remote is not None:
        parts = args.remote.split(":")
        if len(parts) != 2:
            print(f"Invalid remote host string '{args.remote}'")
            exit(1)
        try:
            port = int(parts[1])
        except Exception:
            print(f"Invalid port '{parts[1]}'")
            exit(1)
        remote = Remote(parts[0], port)

    if args.interactive:
        app = Autopwn(args.path[0], remote)
        app.run()
    else:
        binary = Binary(args.path[0])

        goals = list(find_goals(binary))
        vulns = list(find_vulns(binary, goals))

        if args.verbose:
            print(goals)
            print(vulns)

        try:
            output = exploit(binary, goals, vulns, remote, ExploitProgress(args.verbose))
            if output is not None:
                print(f"Flag: {output.decode()}")
        except ExploitError as e:
            print(f"Failed to exploit: {e}")
            exit(1)

if __name__ == "__main__":
    main()
