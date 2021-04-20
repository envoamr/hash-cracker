"""
This module attempts to crack a given hash or list of hashes from a file.
"""

from pathlib import Path, PurePath
from datetime import datetime
import hashop
import time

# the user entered the path to the wordlist relative to his/her current working directory
curr_dir = PurePath(Path.cwd())

to_hash = {
    "lm": hashop.to_lmhash,
    "ntlm": hashop.to_nthash,
    "md4": hashop.to_md4,
    "md5": hashop.to_md5,
    "sha1": hashop.to_sha1,
    "sha256": hashop.to_sha256,
    "sha512": hashop.to_sha512,
}

check_hash = {
    "lm": hashop.check_lmhash,
    "ntlm": hashop.check_nthash,
    "md4": hashop.check_md4,
    "md5": hashop.check_md5,
    "sha1": hashop.check_sha1,
    "sha256": hashop.check_sha256,
    "sha512": hashop.check_sha512,
}


def single(type, hash_str, wordlist):
    """Attempts to crack the given hash by comparing it to strings from the
    provided wordlist.

    Parameters
    ----------
    type : string
        Type of hash function used
    hash : string
        Hash in hex format
    wordlist : string
        Path to wordlist file

    Returns
    -------
    dict
        Contains the number of hash comparisons, time elapsed, and password
    """
    wordlist_path = curr_dir.joinpath(wordlist)

    checked = 0
    password = None
    stime = time.time()

    # loop through each word in the wordlist and check if its hash matches
    with open(wordlist_path, "r") as wordlist_f:
        for line in wordlist_f:
            checked += 1
            line = line.rstrip("\n")
            if check_hash[type](line, hash_str):
                password = line
                break

    return {"checks": checked, "time": time.time() - stime, "password": password}


def multiple(type, hash_file, wordlist):
    """Attempts to crack all the hashes in a given file by comparing them
    to strings from the provided wordlist.

    Parameters
    ----------
    type : string
        Type of hash function used
    hash_file : string
        Path to file of hashes
    wordlist : [type]
        Path to wordlist file

    Returns
    -------
    dict
        Contains the number of hash comparisons, hashes cracked, time elapsed,
        and path to the results
    """
    # get path to hashes file and wordlist
    hashes_path = curr_dir.joinpath(hash_file)
    wordlist_path = curr_dir.joinpath(wordlist)

    # format name of results file
    results_name = datetime.now().strftime(
        f"{Path(hash_file).name}_cracked_%m-%d-%H-%M-%S.txt"
    )
    results_path = Path(curr_dir.joinpath(results_name)).resolve()  # absolute path
    Path(results_path).touch()

    print(f"\nCreated results file {results_path}")
    print(f"\nAttempting to crack the hashes in {Path(hash_file).resolve()}...\n")

    hash_num = 0
    cracked = 0
    stime = time.time()

    # for each hash in the hashes file, loop through each word in the wordlist and
    # check if its hash matches
    with open(hashes_path, "r") as hash_f:
        for hash_str in hash_f:
            hash_num += 1
            hash_str = hash_str.rstrip("\n")
            print(f"{hash_num} {hash_str}", end=" ")

            with open(wordlist_path, "r") as wordlist_f:
                found = False
                for pos_hash in wordlist_f:
                    pos_hash = pos_hash.rstrip("\n")
                    if check_hash[type](pos_hash, hash_str):
                        found = True
                        break

                # hash matched, print the plaintext and store it in the results
                if found:
                    cracked += 1
                    print(f"-> '{pos_hash}'")
                    with open(results_path, "a") as results_f:
                        results_f.write(f"{hash_num} {pos_hash}\n")
                # hash not found
                else:
                    print("not found")
                    # create placeholder to link line numbers between the hashes
                    # file and results file
                    with open(results_path, "a") as results_f:
                        results_f.write(f"{hash_num} \n")

    return {
        "attempted": hash_num,
        "cracked": cracked,
        "time": time.time() - stime,
        "results": results_path,
    }
