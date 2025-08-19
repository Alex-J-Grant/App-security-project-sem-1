import os

import requests
from flask import request
import json
from helperfuncs.logger import main_logger
def get_country_from_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}?token={os.getenv("ipinfo_token")}", timeout=3)
        response.raise_for_status()  # raise for HTTP errors
        data = response.json()
        return data.get("country")  # returns 2-letter code like "SG"
    except requests.exceptions.RequestException as e:
        main_logger.warning(f"IP to country lookup failed on ip {ip}")
        return None
    except ValueError:
        print("[Error] Failed to parse IP info JSON")
        return None

def compare_country(user_country, incoming_ip):
    incoming_country = get_country_from_ip(incoming_ip)
    if incoming_country is None:
        return "unknown"

    if user_country != incoming_country:
        return "mismatch"
    else:
        return "match"
    




