import argparse

from binary import Binary
from goals import find_goals, print_goals
from vulns import find_vulns
from exploit import exploit

def main():
    parser = argparse.ArgumentParser(description="Find and exploit vulnerabilities in a binary")
    parser.add_argument("path", nargs=1)
    parser.add_argument("-g", "--find-goals", action="store_true", help="Find goal functions and print them")
    args = parser.parse_args()

    binary = Binary(args.path[0])

    if args.find_goals:
        goals = find_goals(binary)
        print_goals(goals)
        return

    goals = find_goals(binary)
    vulns = find_vulns(binary)

    if len(goals) == 0:
        print("No goals found")
        exit(1)
    elif len(goals) > 1:
        print("Multiple goals found, choosing first")

    # goals = [
    #     WinFunction("win", 0x401156)
    # ]

    # vulns = [
    #     StackBufferOverflow(0x401183, 0x78, None)
    # ]

    print(goals)
    print(vulns)

    goal = goals[0]
    exploit(binary, goal, vulns)


if __name__ == "__main__":
    main()
