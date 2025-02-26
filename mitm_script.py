import asyncio
from bleak import BleakClient
import json
import requests
import jwt
import time
import os
from Crypto.Cipher import AES

"""
1. Get session string from lock 
2. Obtain unlock command from backend
3. Send the unlock command
"""

# padlock information
RX_CHAR_UUID = "1bc50002-0200-d29e-e511-446c609db825"  # for sending commands
TX_CHAR_UUID = "1bc50003-0200-d29e-e511-446c609db825"  # for receiving notifications
STATE_CHAR_UUID = "1bc50004-0200-d29e-e511-446c609db825"  # for reading session string
PADLOCK_MAC = ""

# API urls
GEOKEY_API_URL = ""
NOKE_CORE_API_URL = "https://coreapi-sandbox.appspot.com"

# API endpoints
UNLOCK_URI = "/api/unlock/"
UNSHACKLE_URI = "/api/unshackle"
UPLOAD_URI = "/upload/"
REFRESH_TOKEN_URI = "/api/RefreshToken"

# authentication tokens
MOBILE_API_KEY = ""  # for Noke Core API
GEOKEY_TOKEN = ""  # for Geokey API


logs = []


def callback(sender, data):
    with open("unlock_commands.txt", "a") as f:
        f.write(f"{data.hex()} ")
    logs.append(data.hex())


def refresh_token(current_token):
    print("Refreshing token...")
    headers = {
        "Authorization": f"Bearer {current_token}",
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/5.0.0-alpha.2",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Host": GEOKEY_API_URL[8:],
    }

    refresh_token = jwt.decode(current_token, algorithms=['HS256'], options={"verify_signature": False})["RefreshToken"]
    refresh_json = {
        "refresh_token": refresh_token,
        "token": current_token
    }
    headers["Content-Length"] = str(len(json.dumps(refresh_json)))

    refresh_response = requests.post(GEOKEY_API_URL + REFRESH_TOKEN_URI, json=refresh_json, headers=headers)
    new_token = refresh_response.json()["data"]["access_token"]

    with open("token.txt", "w") as f:
        f.write(new_token)

    return new_token


def get_unlock_command(token, session_string):
    print("Requesting unlock command from backend...")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/5.0.0-alpha.2",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Host": GEOKEY_BACKEND_URL[8:],
    }

    unlock_json = {
        "mac": PADLOCK_MAC,
        "session": session_string.upper(),
    }
    headers["Content-Length"] = str(len(json.dumps(unlock_json)))

    return requests.post(GEOKEY_BACKEND_URL + UNLOCK_URI, json=unlock_json, headers=headers)


def upload_logs(session_string, logs):
    print("Sending logs to backend...")

    headers = {
        "Content-Type": "application/json",
        "Connection": "close",
        "charset": "utf-8",
        "Authorization": f"Bearer {MOBILE_API_KEY}",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; moto g(8) power Build/RPES31.Q4U-47-35-12)",
        "Host": NOKE_BACKEND_URL[8:],
        "Accept-Encoding": "gzip",
    }

    logs_json = {
        "logs": [
            {
                "session": session_string.upper(),
                "responses": [log.upper() for log in logs if log[:2] == "50"],
                "mac": PADLOCK_MAC,
                "received_time": int(time.time()),
            }
        ]
    }

    headers["Content-Length"] = str(len(json.dumps(logs_json, separators=(',', ':'))))
    return requests.post(NOKE_BACKEND_URL + UPLOAD_URI, json=logs_json, headers=headers)


async def main():
    client = BleakClient(PADLOCK_MAC)
    print("Connecting to the lock...")
    await client.connect()
    print("Getting session string...")
    session_string = await client.read_gatt_char(STATE_CHAR_UUID)
    if not session_string:
        exit(1)

    session_string = session_string.hex().upper()
    print(f"Session string: {session_string}")

    if not os.path.is_file("token.txt"):
        with open("token.txt", "w") as f:
            f.write(GEOKEY_TOKEN)

    with open("token.txt", "r") as f:
        cognito_token = f.readline().strip()

    unlock_response = get_unlock_command(cognito_token, session_string)

    if unlock_response.status_code != 200:
        if unlock_response.status_code == 401:
            print(unlock_response)
            cognito_token = refresh_token(cognito_token)
            unlock_response = get_unlock_command(cognito_token, session_string)
        else:
            print(unlock_response)
            exit(1)

    if unlock_response.status_code != 200:
        print(unlock_response.json())
        exit(1)

    try:
        unlock_command = unlock_response.json()["data"]["command"]
    except:
        print(unlock_response.json())
        exit(1)

    print(f"Unlock command: {unlock_command}")

    await client.write_gatt_char(RX_CHAR_UUID, bytes.fromhex(unlock_command))
    print("Unlock command sent to the lock")
    await asyncio.sleep(0.1)

    with open("unlock_commands.txt", "a") as f:
        f.write(f"{session_string.lower()},{unlock_command},")

    print("Reading notifications...")

    await client.start_notify(TX_CHAR_UUID, callback)
    await asyncio.sleep(5)
    await client.stop_notify(TX_CHAR_UUID)

    print("Disconnecting from the lock...")
    await client.disconnect()

    upload_logs(session_string, logs)

    with open("unlock_commands.txt", "a") as f:
        f.write("\n")


asyncio.run(main())
