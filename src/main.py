import argparse
import os
import sys
import hashop
import crackhash
from pathlib import Path, PurePath

parser = argparse.ArgumentParser()
args = ""


def get_options():
    """Use the argparse module to get command line arguments supplied by the user.
    Only accepts allowed hash types and checks if supplied file paths exist."""

    global args

    options = parser.add_argument_group("flags")
    options.add_argument(
        "-t",
        "--hash-type",
        help="type of hash from the following: lm, ntlm, md4, md5, sha1, sha256, sha512",
        metavar="",
        required=True,
        choices=["lm", "ntlm", "md4", "md5", "sha1", "sha256", "sha512"],
    )
    options.add_argument(
        "-w",
        "--wordlist",
        help="file path to wordlist",
        metavar="",
        type=argparse.FileType("r"),
        required=True,
    )

    hash_group = options.add_mutually_exclusive_group(required=True)
    hash_group.add_argument(
        "-s", "--hash-string", help="hash string to crack", metavar=""
    )
    hash_group.add_argument(
        "-l",
        "--hash-list",
        help="file path to the list of hashes",
        metavar="",
        type=argparse.FileType("r"),
    )

    args = parser.parse_args()


def main():
    """Gets command line arguments and calls the appropriate function to crack hash(es)"""
    get_options()

    # string hash given to crack
    if args.hash_string:
        print(f"\nAttempting to crack hash '{args.hash_string}'...\n")
        result = crackhash.single(args.hash_type, args.hash_string, args.wordlist.name)

        print("Results")
        print(f"Comparisons: {result['checks']}")
        print(f"Time: {result['time']}")
        if result["password"]:
            print(f"Password: '{result['password']}'")
        else:
            print(f"Password not found.")

    # hash file given to crack
    elif args.hash_list:
        result = crackhash.multiple(
            args.hash_type, args.hash_list.name, args.wordlist.name
        )
        print("\nResults")
        print(f'Attempted: {result["attempted"]}')
        print(f'Cracked: {result["cracked"]}')
        print(f'Time: {result["time"]}')
        print(f'Passwords: {result["results"]}')


if __name__ == "__main__":
    main()
