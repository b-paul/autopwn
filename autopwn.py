import argparse
import os
from pwn import log, process, tube

from binary import Binary
from goals import find_goals
from vulns import find_vulns
from exploit import exploit

from mock import patch

def main():
    parser = argparse.ArgumentParser(description="Find and exploit vulnerabilities in a binary")
    parser.add_argument("path", nargs=1)
    parser.add_argument("-g", "--find-goals", action="store_true", help="Find goal functions and print them")
    args = parser.parse_args()

    binary = Binary(args.path[0])

    if args.find_goals:
        goals = find_goals(binary)
        for goal in goals:
            print(goal)
        return

    goals = find_goals(binary)
    vulns = find_vulns(binary, goals)

    print(goals)
    print(vulns)

    exploit(binary, goals, vulns)

def _log(self, level, msg, args, kwargs, msgtype, progress = None):
    pass

def _info(self, msg):
    pass

if __name__ == "__main__":
    with patch.object(process, "_log", _log):
        with patch.object(tube, "_log", _log):
            with patch.object(type(log), "_log", _log):
                main()
