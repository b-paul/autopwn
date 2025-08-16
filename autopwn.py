import argparse
import sys

from binary import Binary
from goals import find_goals
from vulns import find_vulns
from exploit import exploit

def main():
    parser = argparse.ArgumentParser(description='Find and exploit vulnerabilities in a binary')
    parser.add_argument("path", nargs=1)
    args = parser.parse_args()

    binary = Binary(args.path)

    goals = find_goals(binary)
    vulns = find_vulns(binary)

    if len(goals) == 0:
        print("No goals found")
        exit(1)
    elif len(goals) > 1:
        print("Multiple goals found, choosing first")

    goal = goals[0]
    exploit(goal, vulns)


if __name__ == '__main__':
    main()
