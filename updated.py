import tls_client, random, string, threading, requests, json, hashlib, os, base64, colorama, ctypes
import platform
import sys
import re
from datetime import datetime
from websocket   import WebSocket
import json as jsond  # json
import time  # sleep before exit
import binascii  # hex encoding
from uuid import uuid4  # gen random guid
import subprocess  # needed for mac device
import hmac # signature checksum

try:
    if os.name == 'nt':
        import win32security  # get sid (WIN only)
    import requests  # https requests
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("Installing necessary modules....")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        if os.name == 'nt':
            os.system("pip install pywin32")
        os.system("pip install requests")
    print("Modules installed!")
    time.sleep(1.5)
    os._exit(1)


class api:

    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        if len(ownerid) != 10 and len(secret) != 64:
            print("Go to Manage Applications on dashboard, copy python code, and replace code in main.py with that")
            time.sleep(3)
            os._exit(1)
    
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):
        if self.sessionid != "":
            print("You've already initialized!")
            time.sleep(3)
            os._exit(1)

        sent_key = str(uuid4())[:16]
        
        self.enckey = sent_key + "-" + self.secret
        
        post_data = {
            "type": "init",
            "ver": self.version,
            "hash": self.hash_to_check,
            "enckey": sent_key,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            time.sleep(3)
            os._exit(1)

        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                time.sleep(3)
                os._exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                time.sleep(3)
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        
        if json["newSession"]:
            time.sleep(0.1)

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "register",
            "username": user,
            "pass": password,
            "key": license,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully registered")
            self.__load_user_data(json["info"])
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def upgrade(self, user, license):
        self.checkinit()

        post_data = {
            "type": "upgrade",
            "username": user,
            "key": license,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully upgraded user")
            print("Please restart program and login")
            time.sleep(3)
            os._exit(1)
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "login",
            "username": user,
            "pass": password,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("Successfully logged in")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "license",
            "key": key,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("Successfully logged in with license")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def var(self, name):
        self.checkinit()

        post_data = {
            "type": "var",
            "varid": name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()

        post_data = {
            "type": "getvar",
            "var": var_name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(f"NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.\nUse keyauthapp.var(\"{var_name}\") for normal variables");
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()

        post_data = {
            "type": "setvar",
            "var": var_name,
            "data": var_data,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def ban(self):
        self.checkinit()

        post_data = {
            "type": "ban",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def file(self, fileid):
        self.checkinit()

        post_data = {
            "type": "file",
            "fileid": fileid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param, body = "", conttype = ""):
        self.checkinit()

        post_data = {
            "type": "webhook",
            "webid": webid,
            "params": param,
            "body": body,
            "conttype": conttype,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def check(self):
        self.checkinit()

        post_data = {
            "type": "check",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()

        post_data = {
            "type": "checkblacklist",
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()

        post_data = {
            "type": "log",
            "pcuser": os.getenv('username'),
            "message": message,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        self.__do_request(post_data)

    def fetchOnline(self):
        self.checkinit()

        post_data = {
            "type": "fetchOnline",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            if len(json["users"]) == 0:
                return None
            else:
                return json["users"]
        else:
            return None
            
    def fetchStats(self):
        self.checkinit()

        post_data = {
            "type": "fetchStats",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_app_data(json["appinfo"])
            
    def chatGet(self, channel):
        self.checkinit()

        post_data = {
            "type": "chatget",
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None

    def chatSend(self, message, channel):
        self.checkinit()

        post_data = {
            "type": "chatsend",
            "message": message,
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            return False

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(3)
            os._exit(1)

    def changeUsername(self, username):
        self.checkinit()

        post_data = {
            "type": "changeUsername",
            "newUsername": username,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully changed username")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)  

    def logout(self):
        self.checkinit()

        post_data = {
            "type": "logout",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully logged out")
            time.sleep(3)
            os._exit(1)
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)         
            
    def __do_request(self, post_data):
        try:
            response = requests.post(
                "https://keyauth.win/api/1.2/", data=post_data, timeout=10
            )
            
            key = self.secret if post_data["type"] == "init" else self.enckey
            if post_data["type"] == "log": return response.text
                        
            client_computed = hmac.new(key.encode('utf-8'), response.text.encode('utf-8'), hashlib.sha256).hexdigest()
            
            signature = response.headers["signature"]
            
            if not hmac.compare_digest(client_computed, signature):
                print("Signature checksum failed. Request was tampered with or session ended most likely.")
                print("Response: " + response.text)
                time.sleep(3)
                os._exit(1) 
            
            return response.text
        except requests.exceptions.Timeout:
            print("Request timed out. Server is probably down/slow at the moment")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"] or "N/A"
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            sid = win32security.LookupAccountName(None, winuser)[0]  # You can also use WMIC (better than SID, some users had problems with WMIC)
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
        elif platform.system() == 'Darwin':
            output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid

class Utils:
    @staticmethod
    def fetch_buildnum():
        st = time.time()
        try:
            resp = requests.get(f"https://discord.com/assets/{Utils.JS_version()}")
            if resp.status_code == 200:
                buildNum = resp.text.split('"buildNumber",null!==(t="')[1].split('"')[0]
                return int(buildNum), round(time.time() - st, 2)
            else:
                return 232074, None
        except:    
            return 232074, None

    @staticmethod
    def build_xsup():
        data = {
            "os": "Windows",
            "browser": "Chrome",
            "device": "",
            "system_locale": "en-US",
            "browser_user_agent": typees,
            "browser_version": "117.0.0.0",
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": build_num,
            "client_event_source": None
        }
        data = str(data).replace("None", "null")
        return base64.b64encode(str(data).replace("'", '"').replace('": "', '":"').replace('", "', '","').replace('number": ', 'number":').replace(', "client', ',"client').replace('source": ', 'source":').encode()).decode()
        
    @staticmethod
    def JS_version():
        return (requests.get("https://discord.com/app").text.split('"></script><script src="/assets/')[2].split('" integrity')[0])
class UI:
    def clear(title: str=None):
        if platform.system() == 'Windows':
            os.system(f'cls {title if title != None else ""}')  # clear console, change title
        elif platform.system() == 'Linux':
            os.system('clear')  # clear console
            if title != None:
                sys.stdout.write(f"\x1b]0;{title}\x07")  # change title
        elif platform.system() == 'Darwin':
            os.system("clear && printf '\e[3J'")  # clear console
            if title != None:
                os.system(f'''echo - n - e "\033]0;{title}\007"''')  # change title

    def show():
        print("")
        print(f"{colorama.Fore.BLUE}    ____       ____  __  ____           ______         ")
        print(f"{colorama.Fore.BLUE}   / __ \_____/ __ \/ /_/ __ \____     / ____/__  ____ ")
        print(f"{colorama.Fore.BLUE}  / /_/ / ___/ / / / __/ / / / __ \   / / __/ _ \/ __ \\")
        print(f"{colorama.Fore.BLUE} / ____/ /  / /_/ / /_/ /_/ / / / /  / /_/ /  __/ / / /")
        print(f"{colorama.Fore.BLUE}/_/   /_/   \____/\__/\____/_/ /_/   \____/\___/_/ /_/.gg/hcap ")
        print(f"{colorama.Fore.BLUE}                                                       ")
        print("")
        print(f"{colorama.Fore.WHITE}Menu\n")
        print(f"[{colorama.Fore.BLUE}1{colorama.Fore.RESET}] - Start ")
        print(f"[{colorama.Fore.BLUE}2{colorama.Fore.RESET}] - Exit")
        choice = input(f"{colorama.Fore.BLUE}|> {colorama.Fore.WHITE}")
        if choice == "1":
            try:
                with open("config.json") as f:
                    data = json.load(f)
                    license_k = data['license']
                    if license_k == "":
                        raise KeyError
                    else:
                        keyauthapp.license(license_k)
                UI.clear()
                input("Click Enter to Start!")
                UI.clear(title="Starting...")
            except Exception as e:
                UI.clear(title="Invalid License Key")
                input(f"[{colorama.Fore.RED}!{colorama.Fore.RESET}] - Please Provide a Valid license key in the config.json file!")
                os._exit(0)
        else:
            os._exit(1)


class Log:
    global thread_l
    global lock
    def amazing(msg: str, symbol="U"):
        if thread_l:
            lock.acquire()
        print(f"[{colorama.Fore.LIGHTBLACK_EX}{datetime.now().strftime('%H:%M:%S')}{colorama.Fore.RESET}] ({colorama.Fore.BLUE}{symbol}{colorama.Fore.RESET}) - {msg}")
        if thread_l:
            lock.release()
        return
    def good(msg: str, symbol="+"):
        if thread_l:
            lock.acquire()
        print(f"[{colorama.Fore.LIGHTBLACK_EX}{datetime.now().strftime('%H:%M:%S')}{colorama.Fore.RESET}] ({colorama.Fore.LIGHTBLUE_EX}{symbol}{colorama.Fore.RESET}) - {msg}")
        if thread_l:
            lock.release()
        return
    
    def info(msg: str, symbol="="):
        if thread_l:
            lock.acquire()
        print(f"[{colorama.Fore.LIGHTBLACK_EX}{datetime.now().strftime('%H:%M:%S')}{colorama.Fore.RESET}] ({colorama.Fore.LIGHTCYAN_EX}{symbol}{colorama.Fore.RESET}) - {msg}")
        if thread_l:
            lock.release()
        return

    def bad(msg: str, symbol="X"):
        if toggle_errors:
            if thread_l:
                lock.acquire()
            print(f"[{colorama.Fore.LIGHTBLACK_EX}{datetime.now().strftime('%H:%M:%S')}{colorama.Fore.RESET}] ({colorama.Fore.RED}{symbol}{colorama.Fore.RESET}) - {msg}")
            if thread_l:
                lock.release()
        return
    def warn(msg: str, symbol="!"):
        print(f"[{colorama.Fore.LIGHTBLACK_EX}{datetime.now().strftime('%H:%M:%S')}{colorama.Fore.RESET}] ({colorama.Fore.YELLOW}{symbol}{colorama.Fore.RESET}) - {msg}")
        return
    

class Discord:
    global unlocked
    global locked
    global st
    def __init__(self) -> None:
        self.lock = lock
        with open("config.json") as conf:
            self.data = json.load(conf)
        self.unclaimed = self.data['unclaimed']
        self.ws = WebSocket()
        self.cap_key = self.data['capsolver_key']
        self.hcop_key = self.data['hcooptcha_key']
        self.use_hcop = self.data['use_hcooptcha']
        self.capmonster_key = self.data['capmonster_key']
        self.use_hotmailbox = self.data['use_hotmailbox'] if self.data['use_hotmailbox'] == True else False
        self.build_num = build_num
        self.capabilities = 16381
        self.use_capmonster = self.data["use_capmonster"]
        self.thread_lock = thread_l
        self.rl = "The resource is being rate limited."
        self.locked = "You need to verify your account in order to perform this action"
        self.captcha_detected = "captcha-required"
        self.session = tls_client.Session(client_identifier="chrome_117", random_tls_extension_order=True)
        self.proxy = random.choice([prox.strip() for prox in open('proxies.txt')])
        self.x_sup = x_sup
        self.sec_ch_ua = '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"'
        self.toggle_errors = toggle_errors
        self.session.proxies = {
            'https': "http://{}".format(self.proxy),
            'http': "http://{}".format(self.proxy)
        }
        self.ve = False
        _5sim_c = self.data['5sim_countries']
        if self.data['bio']:
            self.bios = [bio.strip() for bio in open("bios.txt")]
        if self.data['random_username']:
            self.username = "".join(random.choice(string.ascii_letters) for x in range(random.randint(4, 6)))
        else:
            self.username = random.choice([prox.strip() for prox in open('usernames.txt', encoding="utf-8")])
            self.username = re.sub('[^a-zA-Z0-9 \n\.]', '', self.username)
            try:
                self.username = self.username.split(" ")[0]
            except:
                pass
        if self.data['verify_email'] and self.data['kopeechka_key'] != "" and len(self.data['kopeechka_domains']) > 0 and self.unclaimed != True:
            self.email_domain = random.choice(self.data['kopeechka_domains'])
            self.email, self.id = self.buy_email()
            self.ve = True
            if self.data['random_username']:
                self.username = self.email.split("@")[0]
            else:
                pass
        else:
            self.email = "".join(random.choice(string.ascii_letters) for x in range(random.randint(4, 7)))
            self.email += str("".join(str(random.randint(1, 9) if random.randint(1, 2) == 1 else random.choice(string.ascii_letters)) for x in range(int(random.randint(6, 8)))))
            self.email += random.choice(["@gmail.com", "@outlook.com"])
        if self.data['password'] == "":
            self.password = "".join(random.choice(string.digits) if random.randint(1, 2) == 1 else random.choice(string.ascii_letters) for x in range(random.randint(8, 24))) + "".join("" if random.randint(1, 2) == 1 else random.choice(["@", "$", "%", "*", "&", "^"]) for x in range(1, 6))
        else:
            self.password = self.data['password']
        self.ua = typees
    
    @staticmethod
    def display_stats():
        while True:
            if locked == 0 and unlocked == 0:
                ur = "0.00%"
            elif unlocked > 0 and locked == 0:
                ur = "100.0%"
            elif locked > 0 and unlocked == 0:
                ur = "0.00%"
            else:
                ur = f"{round(100 - round(locked/unlocked * 100, 2), 2)}%"
            ctypes.windll.kernel32.SetConsoleTitleW(f"Pr0t0n Discord Generator | Unlocked: {unlocked} | Locked: {locked} | Unlock Rate: {ur} | Budget Left: ${round(budget, 4)} | Threads: {threading.active_count() - 2} | Time: {round(time.time() - st, 2)}s | discord.gg/hcap")
            time.sleep(0.5)
    def get_cookies(self):
        url = "https://discord.com/register"
        self.session.headers = {
            'authority': 'discord.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'sec-ch-ua': self.sec_ch_ua,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': self.ua,
        }
        try:
            self.session.cookies = self.session.get(url).cookies
        except Exception as e:
            Log.bad('Unexpected error Fetching Cookies')
            return Discord().begin()
        return
    def buy_email(self):
        if self.data['kopeechka_key'] != "" and not self.use_hotmailbox:
            url = f'https://api.kopeechka.store/mailbox-get-email?api=2.0&site=discord.com&subject=&regex=&mail_type={self.email_domain}&token={self.data["kopeechka_key"]}'
            r = requests.get(url).json()
            try:
                return r['mail'], r['id']
            except:
                Log.bad("Error Buying Mail from kopeechka")
                return Discord().begin()
        elif self.use_hotmailbox and self.data['hotmailbox_key'] != "":
            r = requests.get(f"https://api.hotmailbox.me/mail/buy?apikey={self.data['hotmailbox_key']}&mailcode=HOTMAIL&quantity=1").json()
            try:
                return r['Data']['Emails'][0]['Email'], r['Data']['Emails'][0]['Password'] 
            except Exception as e:
                Log.bad("Error Buying Mail from HotMailBox")
                return Discord().begin()
    def send_verification(self):
        url = 'https://discord.com/api/v9/auth/verify/resend'
        self.session.headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': self.token,
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': self.sec_ch_ua,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.ua,
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'America/New_York',
            'x-super-properties': self.x_sup,
        }
        try:
            r = self.session.post(url).status_code
        except:
            Log.bad(f"Error Sending Verification Code to Email")
            return
        if r == 204 or r == 200:
            Log.good(f"Sent Verification Code --> ({self.email})", symbol="E")
        else:
            Log.bad(f"Error Sending Verification Code to Email")
    def check_token(self):
        global unlocked, locked
        url = "https://discord.com/api/v9/users/@me/affinities/users"
        try:
            response = self.session.get(url)
        except:
            Log.bad("Error Sending Requests to check token")
            return Discord().begin()
        if int(response.status_code) in (400, 401, 403):
            Log.bad(f"Locked Token ({colorama.Fore.RED}{self.token[:25]}..{colorama.Fore.RESET})")
            locked += 1
            return
        else:
            Log.amazing(f"Unlocked Token ({colorama.Fore.LIGHTBLACK_EX}{self.token[:25]}..{colorama.Fore.RESET})")    
            unlocked += 1

            return True
    def ConnectWS(self):
            try:
               self.ws.connect('wss://gateway.discord.gg/?encoding=json&v=9&compress=zlib-stream')
               self.ws.send(json.dumps({
                "op": 2,
                "d": {
                    "token": self.token,
                    "capabilities": self.capabilities,
                    "properties": {
                        "os": "Windows",
                        "browser": "Chrome",
                        "device": "",
                        "system_locale": "en-US",
                        "browser_user_agent": self.ua,
                        "browser_version": "117.0.0.0",
                        "os_version": "10",
                        "referrer": "",
                        "referring_domain": "",
                        "referrer_current": "",
                        "referring_domain_current": "",
                        "release_channel": "stable",
                        "client_build_number": build_num,
                        "client_event_source": None
                    },
                        "presence": {
                        "status": random.choice(['online', 'idle', 'dnd']),
                        "since": 0,
                        "activities": [{
                            "name": "Custom Status",
                            "type": 4,
                            "state": _status,
                            "emoji": ""
                        } if _status != "" else ""],
                        "afk": False
                    },
                    "compress": False,
                    "client_state": {
                        "guild_versions": {},
                        "highest_last_message_id": "0",
                        "read_state_version": 0,
                        "user_guild_settings_version": -1,
                        "user_settings_version": -1,
                        "private_channels_version": "0",
                        "api_code_version": 0
                    }
                }
                }))
            except:
                Log.bad("Error Onling Token")
                return
            Log.good(f"Onlined Token --> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}..{colorama.Fore.RESET})", symbol="O")
            return
    def get_captcha_key(self, site_key: str="4c672d35-0701-42b2-88c3-78380b0db560", enterprise: bool=False, **argv):
        global budget
    #    captcha_key = None
    #    while captcha_key is None:
    #        url = f"http://127.0.0.1:5000/solve?sitekey={site_key}&host=https://discord.com&proxy={self.proxy}"
    #        try:
    #            resp = requests.get(url, timeout=90)
    #            captcha_key = resp.json()['captcha_key']
    #        except:
    #            captcha_key == None
    #        if captcha_key is None:
    #            pass
    #        else:
    #            break
    #    Log.good(f"Solved captcha ({colorama.Fore.LIGHTBLACK_EX}{captcha_key[:40]}..{colorama.Fore.RESET})")
    #    return captcha_key
        service = "https://api.capsolver.com"
        proxy = self.proxy
        used_hcoop = False
        used_capmonster = False
        serv = 'capmonster' if self.use_capmonster and self.capmonster_key != "" else 'capsolver'
        if serv != "capmonster":
            serv = 'hcoptcha' if self.use_hcop and serv == 'capsolver' else 'capsolver'
        if site_key == "4c672d35-0701-42b2-88c3-78380b0db560":
            Log.warn(f"Solving Hcaptcha ({serv})", symbol="/")
        if self.use_capmonster != True and self.use_hcop != True and self.cap_key != "":
            payload = {
                    "clientKey": self.cap_key,
                    "task":
                    {
                        "websiteURL":"https://discord.com/",
                        "websiteKey": site_key,
                    }
            }
            payload["task"]["type"] = "HCaptchaTurboTask"
            payload["task"]["proxy"] = proxy
            payload['task']['userAgent'] = self.ua
        elif self.use_capmonster and self.capmonster_key != "":
            used_capmonster = True
            service = "https://api.capmonster.cloud"
            payload = {
                    "clientKey": self.capmonster_key,
                    "task":
                    {
                        "type":"HCaptchaTaskProxyless",
                        "websiteURL":"https://discord.com/",
                        "websiteKey": site_key,
                        "userAgent": self.ua,
                    }
            }
        elif self.use_hcop and self.hcop_key != "":
            used_hcoop = True
            service = "https://api.hcoptcha.online/api"
            headers = {
                "Content-Type": "application/json"
            }
            payload = {
                "api_key": self.hcop_key, 
                "task_type": "hcaptchaEnterprise", 
                "data": {
                    "rqdata": "",
                    "useragent": self.ua,
                    "sitekey": site_key,
                    "proxy": self.proxy,
                    "host": "discord.com"
                }
            }

        try:
            r = requests.post(f"{service}/createTask", headers=headers, json=payload)

        except Exception as e:
            Log.bad(e)
            return Discord().begin()
        try:
            tked = r.json().get("message")

            if used_hcoop == False:
                if r.json().get("taskId"):
                    taskid = r.json()["taskId"]
                else:
                    Log.bad(f"")
                    return Discord().begin()
            else:
                if r.json().get("task_id"):

                    taskid = r.json()["task_id"]
                else:
                    Log.bad(tked)
                    return Discord().begin()
        except Exception as e:
            Log.bad(e)
            time.sleep(5)
        retries = 0
        while True:
            retries += 1
            try:
                if not used_hcoop:
                    r = requests.post(f"{service}/getTaskResult",json={"clientKey": self.capmonster_key if used_capmonster else self.cap_key,"taskId":taskid})
                    if r.json()["status"] == "ready":
                        if used_capmonster:
                           budget -= 0.0008
                        else:
                            budget -= 0.002
                        cap_pri = r.json()["solution"]["gRecaptchaResponse"][:35]
                        Log.good(f"Solved captcha ({colorama.Fore.LIGHTBLACK_EX}{cap_pri}..{colorama.Fore.RESET})")
                        return r.json()["solution"]["gRecaptchaResponse"]
                else:
                    r = requests.post(f"{service}/getTaskData",json={"api_key": self.hcop_key,"task_id":taskid})
                    if r.json()['task']['state'] == "completed":
                        budget -= 0.0025
                        cap_pri = r.json()["task"]["captcha_key"][:35]
                        Log.good(f"Solved captcha ({colorama.Fore.LIGHTBLACK_EX}{cap_pri}..{colorama.Fore.RESET})")
                        return r.json()["task"]["captcha_key"]
                time.sleep(0.5)
                if retries == 150:
                    raise TimeoutError
            except TimeoutError:
                Log.bad("Failed to solve captcha within 150 seconds.", symbol="#")
            except Exception as e:
                Log.bad("Failed to solve captcha.", symbol="!")
                return Discord().begin()
    @staticmethod
    def nonce():
        date = datetime.now()
        unixts = time.mktime(date.timetuple())
        return str((int(unixts)*1000-1420070400000)*4194304)
    def send_msg(self):
        url = f'https://discord.com/api/v9/channels/{self.data["channel_id"]}/messages'

        payload = {"content":str(self.data['message']),"nonce":f"{Discord.nonce()}","tts":False,"flags":0}
        try:
            r  = self.session.post(url, json=payload).status_code
        except:
            Log.bad("Error Sending Message")
            return
        if r == 200:
            Log.good(f"Successfullly Sent Message --> ({self.data['channel_id']})", symbol="MSG")
        else:
            Log.bad("Error Sending Message")
        return
    
    def add_hs(self):
        url = 'https://discord.com/api/v9/hypesquad/online'
        payload = {
            'house_id': random.choice(['1', '2', '3'])
        }
        try:
            st = self.session.post(url, json=payload)
        except:
            Log.bad(f"Error Adding HypeSquad", symbol="L")
            return
        if st.status_code == 204:
            Log.good(f"Added HypeSquad -> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}..{colorama.Fore.RESET})", symbol="W")
            return
        else:
            if self.locked in str(st.text):
                return Discord().begin()
            else:
                Log.bad(f"Error Adding HypeSquad", "L")
            return
        
    def buy_phonenumber(self):
        op = "any" if len(self.data['5sim_operator']) < 1 else str(random.choice(self.data["5sim_operator"])).lower()
        url = f'https://5sim.net/v1/user/buy/activation/{str(random.choice(self.data["5sim_countries"])).lower()}/{op}/discord'
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.data['5sim_key']}"
        }
        try:
            res = requests.get(url, headers=headers).json()
            return res['id'], res['phone']
        except:
            Log.bad("Error Buying Phone Number")
            return None, None

    
    def join_server(self):
        url = f'https://discord.com/api/v9/invites/{self.data["invite"]}'
        json_data = {
            'session_id': None,
        }
        try:
            r = self.session.post(url, json=json_data)
        except:
            Log.bad("Error Joining Server")
            return
        if r.status_code == 200:
            Log.good(f"Joined Server --> (discord.gg/{self.data['invite']})", "*")
            if self.data['channel_id'] != "" and self.data['message'] != "":
                self.send_msg()
        elif r.status_code == 400:
            self.session.headers['x-captcha-key'] = str(self.get_captcha_key(r.json()['captcha_sitekey']))
        else:
            Log.bad("Error Joining Server")
        return
    
    
    def verify_email(self):
        for i in range(40):
            ra = {
                "value": None
            }
            if self.data['kopeechka_key'] != "" and not self.data['use_hotmailbox']:
                url = f'https://api.kopeechka.store/mailbox-get-message?full=1&id={self.id}&token={self.data["kopeechka_key"]}'
                r = requests.get(url).json()
                if r['value'] == "WAIT_LINK":
                    time.sleep(0.75)
                else:
                    ra['value'] = r['value']
            else:
                url = f"https://getcode.hotmailbox.me/discord?email={self.email}&password={self.id}&timeout=60"
                r = requests.get(url).json()
                if r['Message'] == "Timeout":
                    break
                else:
                    if r['VerificationCode'] != None:
                        ra["value"] = r['VerificationCode']
                    else:
                        break
            if ra['value'] != None:
                try:
                    sess = tls_client.Session(client_identifier="chrome_117", random_tls_extension_order=True)
                    sess2 = tls_client.Session(client_identifier="chrome_117", random_tls_extension_order=True)
                    sess.proxies = self.session.proxies
                    sess2.proxies = self.session.proxies
                    sess.headers = {
                        'authority': 'click.discord.com',
                        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                        'accept-language': 'en-US,en;q=0.9',
                        'sec-ch-ua': self.sec_ch_ua,
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'document',
                        'sec-fetch-mode': 'navigate',
                        'sec-fetch-site': 'none',
                        'sec-fetch-user': '?1',
                        'upgrade-insecure-requests': '1',
                        'user-agent': self.ua,
                    }
                    sess2.headers = {
                        'authority': 'discord.com',
                        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                        'accept-language': 'en-US,en;q=0.9',
                        # 'cookie': '__dcfduid=a8874f60444b11ee8455a3c28bf407be; __sdcfduid=a8874f61444b11ee8455a3c28bf407be3e83987c81a4725b33f6cc672b78f4d4066c88fb9c8e20c00b7260952d6bc079; __cfruid=dae4751451995409499acffbf58adbb59fe86194-1693080223; _cfuvid=b7_SBrybQSHwbuVfFOUSuysXqNanbY4xCGcfG7Slvgo-1693080223584-0-604800000; cf_clearance=IE0_FsUIy3J1eJ_oj8_uAleehjKfOOlWsrShUBSRAD0-1693080225-0-1-4bd91675.581adde9.1cd84995-0.2.1693080225; locale=en-US; _gcl_au=1.1.1170432290.1693080571; _ga=GA1.1.1746112378.1693080571; OptanonConsent=isIABGlobal=false&datestamp=Sat+Aug+26+2023+16%3A09%3A59+GMT-0400+(Eastern+Daylight+Time)&version=6.33.0&hosts=&landingPath=https%3A%2F%2Fdiscord.com%2F&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1; _ga_Q149DFWHT7=GS1.1.1693080571.1.1.1693080599.0.0.0',
                        'sec-ch-ua': self.sec_ch_ua,
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'document',
                        'sec-fetch-mode': 'navigate',
                        'sec-fetch-site': 'none',
                        'sec-fetch-user': '?1',
                        'upgrade-insecure-requests': '1',
                        'user-agent': self.ua,
                    }
                    try:
                        link = str(ra['value']).replace("\\", "")
                    except:
                        pass
                    try:
                        res = str(sess.get(link).headers['Location'])
                    except:
                        Log.bad("Unexpected Error while Verifying Email")
                        break
                    try:
                        r = sess2.get("https://discord.com/verify")
                    except:
                        Log.bad("Unexpected Error while Verifying Email")
                        break
                    email_token = res.split("#token=")[1]
                    sess.headers = {
                        'authority': 'discord.com',
                        'accept': '*/*',
                        'accept-language': 'en-US,en;q=0.9',
                        'referer': 'https://discord.com/verify',
                        'sec-ch-ua': self.sec_ch_ua,
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'empty',
                        'sec-fetch-mode': 'cors',
                        'sec-fetch-site': 'same-origin',
                        'user-agent': self.ua,
                        'x-context-properties': 'eyJsb2NhdGlvbiI6IlZlcmlmeSBFbWFpbCJ9',
                        'x-debug-options': 'bugReporterEnabled',
                        'x-discord-locale': 'en-US',
                        'x-discord-timezone': 'America/New_York',
                        'x-super-properties': self.x_sup,
                    }
                    try:
                        fingerprint = sess.get("https://discord.com/api/v9/experiments?with_guild_experiments=true").json()['fingerprint']
                    except:
                        Log.bad("Unexpected Error while Verifying Email")
                        break
                    sess2.headers = {
                        'authority': 'discord.com',
                        'accept': '*/*',
                        'accept-language': 'en-US,en;q=0.9',
                        # 'cookie': '__dcfduid=a8874f60444b11ee8455a3c28bf407be; __sdcfduid=a8874f61444b11ee8455a3c28bf407be3e83987c81a4725b33f6cc672b78f4d4066c88fb9c8e20c00b7260952d6bc079; __cfruid=dae4751451995409499acffbf58adbb59fe86194-1693080223; _cfuvid=b7_SBrybQSHwbuVfFOUSuysXqNanbY4xCGcfG7Slvgo-1693080223584-0-604800000; cf_clearance=IE0_FsUIy3J1eJ_oj8_uAleehjKfOOlWsrShUBSRAD0-1693080225-0-1-4bd91675.581adde9.1cd84995-0.2.1693080225; locale=en-US; _gcl_au=1.1.1170432290.1693080571; _ga=GA1.1.1746112378.1693080571; OptanonConsent=isIABGlobal=false&datestamp=Sat+Aug+26+2023+16%3A09%3A59+GMT-0400+(Eastern+Daylight+Time)&version=6.33.0&hosts=&landingPath=https%3A%2F%2Fdiscord.com%2F&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1; _ga_Q149DFWHT7=GS1.1.1693080571.1.1.1693080599.0.0.0',
                        'referer': 'https://discord.com/verify',
                        'sec-ch-ua': self.sec_ch_ua,
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'empty',
                        'sec-fetch-mode': 'cors',
                        'sec-fetch-site': 'same-origin',
                        'user-agent': self.ua,
                        'x-context-properties': 'eyJsb2NhdGlvbiI6IlZlcmlmeSBFbWFpbCJ9',
                        'x-debug-options': 'bugReporterEnabled',
                        'x-discord-locale': 'en-US',
                        'x-discord-timezone': 'America/New_York',
                        'x-super-properties': self.x_sup,
                    }
                    url = 'https://discord.com/api/v9/auth/verify'
                    sess2.headers = {
                        'authority': 'discord.com',
                        'accept': '*/*',
                        'accept-language': 'en-US,en;q=0.9',
                        'content-type': 'application/json',
                        'origin': 'https://discord.com',
                        'referer': 'https://discord.com/verify',
                        'sec-ch-ua': self.sec_ch_ua,
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'empty',
                        'sec-fetch-mode': 'cors',
                        'sec-fetch-site': 'same-origin',
                        'user-agent': self.ua,
                        'x-debug-options': 'bugReporterEnabled',
                        'x-discord-locale': 'en-US',
                        'x-discord-timezone': 'America/New_York',
                        'x-fingerprint': fingerprint,
                        'x-super-properties': self.x_sup,
                    }
                    payload = {
                        "token": email_token
                    }
                    try:
                        response = sess2.post(url, json=payload)
                    except:
                        Log.bad("Unexpected Error while Verifying Email")
                        break
                    if response.status_code == 200:
                        Log.good(f"Successfully Verified Email --> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}{colorama.Fore.RESET}..)", "EV")
                        self.token = response.json()['token']
                        self.session.headers['authorization'] = str(self.token)
                        break
                    elif response.status_code == 400:
                        if self.data["verify_email"]:
                            Log.warn("Solving Email Captcha")
                            payload = {
                                "token": email_token,
                                "captcha_key": str(self.get_captcha_key(response.json()['captcha_sitekey']))
                            }
                            try:
                                self.token = sess2.post(url, json=payload).json()['token']
                                Log.good(f"Verified Email with Captcha --> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}{colorama.Fore.RESET}..)", "EV")
                                return
                            except:
                                Log.bad("Failed to Verify Email with Captcha", "GAY")
                                return
                    else:
                        Log.bad("Unexpected Error while Verifying Email")
                        break
                except:
                    Log.bad("Unexpected Error while Verifying Email")
                    break
        try:
            self.session.headers['x-fingerprint'] = ""
        except:
            pass 
        return
    
    def add_pfp(self):
        url = 'https://discord.com/api/v9/users/@me'
        folder_path = "./pfps"
        image_files = [file for file in os.listdir(folder_path) if file.endswith(('.jpg', '.jpeg', '.png'))]
        if not image_files:
            Log.warn("Cannot add PFP, no pfps found in folder /pfps")
            return
        random_image = random.choice(image_files)
        exten = random_image.split(".")[1]
        image_path = os.path.join(folder_path, random_image)

        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
        json_data = {
            "avatar": f"data:image/{exten};base64,{(encoded_string.decode('utf-8'))}",
        }
        try:
            r = self.session.patch("https://discord.com/api/v9/users/@me", json=json_data).json()['id']
            Log.good(f"Added PFP --> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}..{colorama.Fore.RESET})", "P")
        except:
            try:
                if self.locked in str(r.text):
                    return Discord().begin()
                else:
                    return
            except:
                Log.bad("Error Adding PFP")
        return
    
    def add_pronouns(self):
        url = "https://discord.com/api/v9/users/%40me/profile"
        payload = {"pronouns":self.data['pronoun']}
        try:
            res = self.session.patch(url, json=payload)
        except:
            return
        if res.status_code == 200:
            Log.good(f"Added Pronoun --> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}{colorama.Fore.RESET})", symbol="P")
        else:
            if self.locked in str(res.text):
                return Discord().begin()
            else:
                Log.bad("Error Adding Pronoun")
        return
    def add_bio(self):
        url = 'https://discord.com/api/v9/users/%40me/profile'
        payload = {
            "bio": str(random.choice(self.bios))
        }
        try:
            r = self.session.patch(url, json=payload)
        except:
            Log.bad("Error Adding Bio")
            return
        if r.status_code == 200:
            Log.good(f"Added Bio --> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}..{colorama.Fore.RESET})", "B")
        else:
            Log.bad("Error Adding Bio")
        return
    def enable_devmode(self):
        url = 'https://discord.com/api/v9/users/@me/settings-proto/1'
        payload = {
            "settings": "agIQAQ=="
        }
        try:
            r = self.session.patch(url, json=payload)
            r_s = r.status_code
        except:
            Log.bad("Error Enabling Devmode")
            return
        if r_s == 200:
            Log.good(f"Enabled Devmode --> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}..{colorama.Fore.RESET})", "DEV")
        else:
            Log.bad("Error Enabling Devmode")
        return
    def get_fingerprint(self):
        url = 'https://discord.com/api/v9/experiments?with_guild_experiments=true'
        self.session.headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'referer': 'https://discord.com/register',
            'sec-ch-ua': self.sec_ch_ua,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.ua,
            'x-context-properties': 'eyJsb2NhdGlvbiI6IlJlZ2lzdGVyIn0=',
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'America/New_York',
            'x-super-properties': self.x_sup,
        }
        try:
            r = self.session.get(url)
            return r.json()['fingerprint']
        except:
            Log.bad("Error Fetching Fingerprint")
            return Discord().begin()
        
    def send_sms(self):
        new_session = tls_client.Session(client_identifier="chrome_117", random_tls_extension_order=True)
        new_session2 = tls_client.Session(client_identifier="chrome_117", random_tls_extension_order=True)
        new_session.proxies = self.session.proxies
        new_session2.proxies = self.session.proxies
        new_session.headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': self.token,
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': self.sec_ch_ua,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.ua,
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'America/New_York',
            'x-super-properties': self.x_sup,
        }
        json_data = {
            'phone': str(self.phone),
            'change_phone_reason': 'user_settings_update',
        }
        try:
            res = new_session.post("https://discord.com/api/v9/users/@me/phone", json=json_data)
        except Exception as e:
            Log.bad("Error Adding Phone Number")
            return 
        if res.status_code == 204:
            Log.good(f"Added Phone Number ({self.phone})")
            return True
        else:
            if self.data['solve_phone_captcha']:
                try:
                    new_session.cookies = res.cookies
                    ck = res.json()['captcha_sitekey']
                except KeyError:
                    Log.bad(f"{self.phone} Was Detected as a VOIP Number", "@")
                except:
                    Log.bad("Error Adding Phone Number")
                    return
                try:
                    headers = {
                        'authority': 'discord.com',
                        'accept': '*/*',
                        'accept-language': 'en-US,en;q=0.9',
                        'authorization': self.token,
                        'content-type': 'application/json',
                        'origin': 'https://discord.com',
                        'referer': 'https://discord.com/channels/@me',
                        'sec-ch-ua': self.sec_ch_ua,
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'empty',
                        'sec-fetch-mode': 'cors',
                        'sec-fetch-site': 'same-origin',
                        'user-agent': self.ua,
                        'x-captcha-key': str(self.get_captcha_key(site_key=str(ck))),
                        'x-debug-options': 'bugReporterEnabled',
                        'x-discord-locale': 'en-US',
                        'x-discord-timezone': 'America/New_York',
                        'x-super-properties': self.x_sup,
                    }
                    res = new_session2.post("https://discord.com/api/v9/users/@me/phone", headers=headers, json=json_data)
                except Exception as e:
                    Log.bad("Error Adding Phone!")
                    return
                if res.status_code == 204:
                    Log.good(f"Added Phone Number awaiting sms --> ({self.phone})")
                    code = self.fetch_sms()
                    if code == False:
                        return
                    else:
                        url = "https://discord.com/api/v9/phone-verifications/verify"
                        data = {"phone": self.phone,"code": code}
                        try:
                            res = new_session.post(url, json=data)
                            token = res.json()['token']
                        except:
                            Log.bad("Error getting SMS Token!")
                            return
                        if res.status_code == 200:
                            url = "https://discord.com/api/v9/users/@me/phone"
                            data = {"phone_token": token,"password": self.password,"change_phone_reason":"user_settings_update"}
                            try:
                                res = new_session.post(url, json=data)
                            except:
                                Log.bad("Error Verigying SMS code!")
                                return
                            if res.status_code == 204 or res.status_code == 200:
                                try:
                                    Log.good(f"Successfully Verified Phone Number --> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}{colorama.Fore.RESET}..)")
                                except:
                                    Log.bad("Error Verifying SMS Code!")
                                return
                            else:
                                Log.bad("Error Verifying SMS Code!")
                                return
                        else:
                            Log.bad("Error Sumbitting SMS Code!")
                            return
                else:
                    Log.bad("Error Adding Number")
            else:
                Log.bad("Phone Number on Captcha")
                return

    def fetch_sms(self):
        for i in range(150):
            url = f"https://5sim.net/v1/user/check/{self.id}"
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self.data['5sim_key']}"
            }
            try:
                res = requests.get(url, headers=headers).json()['sms']
                if len(res) == 0:
                    time.sleep(0.5)
                else:
                    code = res[0]['code']
                    Log.good(f"Fetched SMS code --> ({code})", "SMS")
                    return code
            except:
                time.sleep(0.5)
        Log.bad("Couldn't Fetch SMS Code!")
        return False

    def create_acct(self):
        url = 'https://discord.com/api/v9/auth/register'
        if not self.unclaimed:
            self.display_name = self.username
            self.session.headers = {
                'authority': 'discord.com',
                'accept': '*/*',
                "accept-encoding": "gzip, deflate, br",
                'accept-language': 'en-US,en;q=0.9',
                'content-type': 'application/json',
                'origin': 'https://discord.com',
                'referer': 'https://discord.com/register',
                'sec-ch-ua': self.sec_ch_ua,
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': self.ua,
                'x-captcha-key': str(self.get_captcha_key()),
                'x-debug-options': 'bugReporterEnabled',
                'x-discord-locale': 'en-US',
                'x-discord-timezone': 'America/New_York',
                'x-fingerprint': self.fp,
                'x-super-properties': self.x_sup,
            }
            payload = {
                'fingerprint': self.fp,
                'email': self.email,
                'username': self.username + "".join(random.choice(string.ascii_letters) for x in range(random.randint(1, 3))),
                'global_name': self.display_name,
                'password': self.password,
                'invite': self.data["invite"] if self.data["invite"] != None else None,
                'consent': True,
                'date_of_birth': f'{random.randint(1980, 2001)}-{random.randint(1, 10)}-{random.randint(1, 10)}',
                'gift_code_sku_id': None,
                'unique_username_registration': True,
            }
        else:
            self.session.headers = {
                'authority': 'discord.com',
                'accept': '*/*',
                "accept-encoding": "gzip, deflate, br",
                'accept-language': 'en-US,en;q=0.9',
                "connection": "keep-alive",
                'content-type': 'application/json',
                'origin': 'https://discord.com',
                'referer': 'https://discord.com/',
                'sec-ch-ua': self.sec_ch_ua,
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': self.ua,
                'x-fingerprint': self.fp,
                'x-track': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzExNy4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTE3LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjk5OTksImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9',
            }
            payload = {
                'consent': True,
                'fingerprint': self.fp,
                'captcha_key': str(self.get_captcha_key()),
                'global_name': self.username,
                'unique_username_registration': True,
            }
        try:
            r = self.session.post(url, json=payload)
            self.token = r.json()['token']
        except Exception as e:
            try:
                if self.rl in str(r.text):
                    Log.bad("IP Ratelimit (Registration)", "X")
                    return Discord().begin()
            except tls_client.sessions.TLSClientExeption:
                Log.bad("TLS Proxy Timeout Error", "X")
                return Discord().begin()
            except:
                pass
            
            Log.bad("Error Creating Account!")
            return Discord().begin()
        self.session.headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': self.token,
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': self.sec_ch_ua,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.ua,
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'America/New_York',
            'x-super-properties': self.x_sup,
        }

        if self.unclaimed:
            url = "https://discord.com/api/v9/users/@me"
            data = {"date_of_birth":f'{random.randint(1980, 1999)}-{random.randint(1, 10)}-{random.randint(1, 10)}'}
            try:
                r = self.session.patch(url, json=data).status_code
            except:
                Log.bad("Error Adding DOB to unclaimed")
                return
            if r == 200:
                Log.good(f"Added DOB to Unclaimed --> ({colorama.Fore.LIGHTBLACK_EX}{self.token[:20]}{colorama.Fore.RESET}..)", "D")
            else:
                Log.bad("Error Adding DOB to unclaimed")
                return
        self.ConnectWS()
        res = self.check_token()
        if res:
            if self.ve:
                if not self.unclaimed:
                    self.send_verification()
                    self.verify_email()
                    with open("tokens.txt", 'a+') as f:
                        if self.thread_lock:
                            self.lock.acquire()
                        if not self.unclaimed:
                            f.write(f"{self.email}:{self.password}:{self.token}\n")
                        else:
                            f.write(f"{self.token}\n")
                        if self.thread_lock:
                            self.lock.release()
                    self.session.headers = {
                        'authority': 'discord.com',
                        'accept': '*/*',
                        'accept-language': 'en-US,en;q=0.9',
                        'authorization': self.token,
                        'content-type': 'application/json',
                        'origin': 'https://discord.com',
                        'referer': 'https://discord.com/channels/@me',
                        'sec-ch-ua': self.sec_ch_ua,
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'sec-fetch-dest': 'empty',
                        'sec-fetch-mode': 'cors',
                        'sec-fetch-site': 'same-origin',
                        'user-agent': self.ua,
                        'x-debug-options': 'bugReporterEnabled',
                        'x-discord-locale': 'en-US',
                        'x-discord-timezone': 'America/New_York',
                        'x-super-properties': self.x_sup,
                    }
                else:
                    pass
            if self.data["verify_phone"]:
                d = self.buy_phonenumber()
                self.id, self.phone = d[0], d[1]
                if self.id is None or self.phone is None:
                    pass
                else:
                    self.send_sms()
            self.session.headers = {
                'authority': 'discord.com',
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'authorization': self.token,
                'content-type': 'application/json',
                'origin': 'https://discord.com',
                'referer': 'https://discord.com/channels/@me',
                'sec-ch-ua': self.sec_ch_ua,
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': self.ua,
                'x-debug-options': 'bugReporterEnabled',
                'x-discord-locale': 'en-US',
                'x-discord-timezone': 'America/New_York',
                'x-super-properties': self.x_sup,
            }
            if not self.ve:
                with open("tokens.txt", 'a+') as f:
                    if self.thread_lock:
                        self.lock.acquire()
                    if not self.unclaimed:
                        f.write(f"{self.email}:{self.password}:{self.token}\n")
                    else:
                        f.write(f"{self.token}\n")
                    if self.thread_lock:
                        self.lock.release()
            if self.data['pronoun'] != "":
                self.add_pronouns()
            if self.data['add_pfp']:
                self.add_pfp()
            if self.data['bio']:
                self.add_bio()
            if self.data['enable_devmode']:
                self.enable_devmode()
            if self.data['add_hypesquad']:
                self.add_hs()
            if self.data['invite'] != "":
                self.join_server()
        return
    def begin(self):
        if budget <= 0:
            return
        self.get_cookies()
        self.fp = self.get_fingerprint()
        self.create_acct()
        return Discord().begin()
def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest

if __name__ == "__main__":
    lock = threading.Lock()
    colorama.init(autoreset=True)
    keyauthapp = api(
        name = "cd6-gen",
        ownerid = "zqK9dtEota",
        secret = "3d57b8894baccb025300192d32cc2232bb1e4365b1fe0eeea0e4857e78bd2306",
        version = "1.2",
        hash_to_check = getchecksum()
    )
    typees = (input("WebType: "))
    UI.show()
    build_num, elapsed_time = Utils.fetch_buildnum()
    x_sup = Utils.build_xsup()
    thds = int(input("Threads: "))
    UI.clear()
    with open("config.json") as f:
        f = json.load(f)
        toggle_errors = f['show_errors']
        cap_key = f['capsolver_key']
        thread_l = f['thread_lock']
        _status = f['status']
        budget = f['budget']
    Log.amazing(f"Fetched Current Build Number in {'N/A' if elapsed_time is None else elapsed_time}s --> ({build_num})", "&")
    Log.amazing(f"Built Latest X-SUPER-PROPERTIES --> ({x_sup[:55]}..)", "&")
    unlocked = 0
    locked = 0
    st = time.time()
    proxy = random.choice([prox.strip() for prox in open('proxies.txt')])
    for i in range(thds):
        discord = Discord()
        threading.Thread(target=discord.begin).start()
    if f['display_title']:
        Ds = Discord()
        threading.Thread(target=Ds.display_stats).start()
