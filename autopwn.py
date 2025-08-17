import argparse
import logging

from binary import Binary
from goals import find_goals
from vulns import find_vulns
from exploit import exploit, ExploitError
from tui import Autopwn

def main():
    parser = argparse.ArgumentParser(description="Find and exploit vulnerabilities in a binary")
    parser.add_argument("path", nargs=1)
    parser.add_argument("-v", "--verbose", action="store_true", help="Print extra debug information")
    parser.add_argument("-i", "--interactive", action="store_true", help="Enable the pwn TUI")
    args = parser.parse_args()

    logging.getLogger("angr").setLevel(999)

    if args.interactive:
        app = Autopwn(args)
        app.run()
    else:
        binary = Binary(args.path[0])

        goals = find_goals(binary)
        vulns = find_vulns(binary, goals)

        if args.verbose:
            print(goals)
            print(vulns)

        try:
            output = exploit(binary, goals, vulns)
            if output is not None:
                print(f"Flag: {output.decode()}")
        except ExploitError as e:
            print(f"Failed to exploit: {e}")
            exit(1)

if __name__ == "__main__":
    main()
