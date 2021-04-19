# Hash Cracker with Python

## Plan

**Objective**: Crack LM, NTLMv1, NTLMv2, MD4, MD5, SHA1, SHA256, and SHA512 hash functions.

**Idea**: Each given hash is compared against hashed values of a wordlist file and added to a list of matches if found.

**Cracking MD4, MD5, SHA1, SHA256, SHA512**

The `hashlib` Python library supports these hash functions, according to `hashlib.algorithms_guaranteed` and `hashlib.algorithms_available`.

## Example

### Single hash

Go to [https://gchq.github.io/CyberChef/#recipe=MD5()](https://gchq.github.io/CyberChef/#recipe=MD5()) and type `shadow` in the Input box. The MD5 is `3bf1114a986ba87ed28fc1b5884fc2f8`.

`python main.py -t md5 -w test/wordlist_ex.txt -s 3bf1114a986ba87ed28fc1b5884fc2f8`

### Multiple hashes

`python main.py -t md5 -w test/wordlist_ex.txt -l test/hashes_ex.txt`