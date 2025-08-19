from user_agents import parse
from flask import request

def describe_device(request_usr_agent):


    user_agent = parse(str(request_usr_agent))

    # Device type
    if user_agent.is_mobile:
        device_type = "mobile phone"
    elif user_agent.is_tablet:
        device_type = "tablet"
    elif user_agent.is_pc:
        device_type = "computer"
    else:
        device_type = "device"

    # OS
    os = user_agent.os.family or "Unknown OS"

    # Browser
    browser = user_agent.browser.family or "Unknown browser"

    return f"{os} {device_type} using {browser}"
