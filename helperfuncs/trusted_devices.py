# helperfuncs/trusted_devices.py
import os
import secrets
from models.trusted_device import TrustedDevice, UserTrustedDevice
from extensions import db
from datetime import datetime, timezone
import hashlib
secret = os.getenv("SECRET_KEY")


def generate_device_token():
    return secrets.token_urlsafe(32)

def save_trusted_device(user_id, device_token, verified=False):

    device = TrustedDevice.query.filter_by(device_token=device_token).first()
    if not device:
        device = TrustedDevice(device_token=device_token, verified=verified)
        db.session.add(device)
        db.session.commit()

    link = UserTrustedDevice.query.filter_by(user_id=user_id, device_id=device.id).first()
    if not link:
        link = UserTrustedDevice(user_id=user_id, device_id=device.id)
        db.session.add(link)
        db.session.commit()
    return device

def mark_device_verified(device_token):

    device = TrustedDevice.query.filter_by(device_token=device_token).first()
    if device and not device.verified:
        device.verified = True
        device.verified_at = datetime.now(timezone.utc)
        db.session.commit()

def is_trusted_device(user_id, device_token):

    if not device_token:
        return False
    device = TrustedDevice.query.filter_by(device_token=device_token, verified=True).first()
    if not device:
        return False
    link = UserTrustedDevice.query.filter_by(user_id=user_id, device_id=device.id).first()
    if link:
        device.last_used = datetime.now(timezone.utc)
        db.session.commit()
        return True
    return False


def rotate_trusted_device(user_id, old_token):
    device = TrustedDevice.query.filter_by(device_token=old_token, verified=True).first()
    if not device:
        return None

    # generate a new token
    new_token = generate_device_token()

    # update db
    device.device_token = new_token
    device.last_used = datetime.now(timezone.utc)
    db.session.commit()

    return new_token


def trusted_cookie_name(user_id:str | int) -> str:
    name = f"td_{hashlib.sha256(f'{user_id}{secret}'.encode()).hexdigest()}"
    return name

def temp_cookie_name(user_id:str | int) -> str:
    name = f"tpd_{hashlib.sha256(f'{user_id}{secret}'.encode()).hexdigest()}"
    return name
