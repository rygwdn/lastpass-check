#!/usr/bin/env python
# encoding: utf-8

"""
This is a script for checking if a given input is a password in a LastPass database.

You can easily package it as a single file (e.g. for use in a script) by doing:
    pyinstaller --onefile --console lastpass-check.py
"""

from lastpass import Fetcher, Parser
import getpass
import bcrypt
from multiprocessing import Pool
import os.path
import json
import sys
from Tkinter import Tk, N, S, W, E, StringVar
import ttk


ROUNDS = 8
HASHES_FILE = "~/.lp_hashes"
CHUNK_SIZE = 5

def guiLogin():
    root = Tk()

    root.title("Enter Lastpass login")

    mainframe = ttk.Frame(root, padding="3 3 12 12")
    mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
    mainframe.columnconfigure(0, weight=1)
    mainframe.rowconfigure(0, weight=1)

    username = StringVar()
    password = StringVar()
    ret = []

    def done(*args):
        ret.append((username.get(), password.get()))
        root.destroy()

    ttk.Label(mainframe, text="Username:").grid(column=1, row=1, sticky=(W, E))
    username_entry = ttk.Entry(mainframe, width=7, textvariable=username)
    username_entry.grid(column=2, row=1, sticky=(W, E))

    ttk.Label(mainframe, text="Password:").grid(column=1, row=2, sticky=(W, E))
    pass_entry = ttk.Entry(mainframe, width=7, textvariable=password)
    pass_entry.grid(column=2, row=2, sticky=(W, E))

    ttk.Button(mainframe, text="Login", command=done).grid(column=2, row=3, sticky=W)

    for child in mainframe.winfo_children(): child.grid_configure(padx=5, pady=2)

    username_entry.focus()
    root.bind('<Return>', done)
    root.bind('<Escape>', lambda event: root.destroy())

    root.lift()
    root.call('wm', 'attributes', '.', '-topmost', True)
    root.after_idle(root.call, 'wm', 'attributes', '.', '-topmost', False)

    root.mainloop()

    return ret and ret[-1] or None


def hash_pw(password):
    # Hash a password for the first time, with a certain number of rounds
    hashed = bcrypt.hashpw(password.strip(), bcrypt.gensalt(ROUNDS))
    return hashed

def get_hashes(username, password, pool=None):
    if not pool:
        pool = Pool()

    fetcher = Fetcher.fetch(username, password)
    parser = Parser.parse(fetcher.blob, fetcher.encryption_key)
    accounts = parser.chunks['ACCT']
    passwords = set(a["password"] for a in accounts if a["password"])

    pass_hashes = list(pool.imap_unordered(hash_pw, passwords, chunksize=CHUNK_SIZE))
    min_length = len(min(passwords, key=len))
    max_length = len(max(passwords, key=len))

    return pass_hashes, max_length, min_length

def passwords_equal(params):
    password, hashed = params
    return bcrypt.hashpw(password, hashed) == hashed

def contains_password(password_hashes, password, pool=None):
    if not pool:
        pool = Pool()
    password = password.strip().encode('utf-8')
    pairs = [(password, hashed.encode('utf-8')) for hashed in password_hashes]
    for value in pool.imap_unordered(passwords_equal, pairs, chunksize=CHUNK_SIZE):
        if value:
            return True
    return False

def store_passwords():
    username = raw_input("Lastpass username: ")
    password = getpass.getpass("Lastpass password: ")

    passwords, longest, shortest = get_hashes(username, password)
    output = {
        "longest": longest,
        "shortest": shortest,
        "passwords": passwords
    }

    with open(os.path.expanduser(HASHES_FILE), "w") as outf:
        json.dump(output, outf)

    return 0

def is_password(pass_to_check=None):
    try:
        with open(os.path.expanduser(HASHES_FILE), "r") as inf:
            data = json.load(inf)
    except:
        return False

    if not pass_to_check:
        pass_to_check = getpass.getpass("Check for: ")
    pass_to_check = pass_to_check.strip()

    contains = False
    if data["shortest"] <= len(pass_to_check) <= data["longest"]:
        contains = contains_password(data["passwords"], pass_to_check)

    return contains

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Check if a string is a lastpass password.')
    parser.add_argument('--stdin', action='store_true', help='Get password from stdin')
    parser.add_argument('--echo-if-missing', action='store_true', help='Get possible password from stdin and echo back if not in LastPass')
    parser.add_argument('--login', '--update', dest='login', action='store_true', help='Fetch lastpass passwords')
    args = parser.parse_args()

    #username, password = guiLogin()

    if args.login:
        store_passwords()

    if args.echo_if_missing:
        input = sys.stdin.read()
        if not is_password(input):
            sys.stdout.write(input)
    elif args.stdin:
        sys.exit(not is_password(sys.stdin.read()))
    else:
        sys.exit(not is_password())
