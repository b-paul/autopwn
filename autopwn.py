import sys

from binary import Binary
from goals import find_goals
from vulns import find_vulns

def main():
    binary = Binary(sys.argv[1])

    goals = find_goals(binary)
    vulns = find_vulns(binary)


if __name__ == '__main__':
    main()
