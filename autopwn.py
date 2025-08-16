import argparse
import sys

from binary import Binary
from goals import find_goals
from vulns import find_vulns

def main():
    parser = argparse.ArgumentParser(description='Find and exploit vulnerabilities in a binary')
    parser.add_argument("path", nargs=1)
    args = parser.parse_args()

    binary = Binary(args.path)

    goals = find_goals(binary)
    vulns = find_vulns(binary)


if __name__ == '__main__':
    main()
