# helperfuncs/trusted_devices.py
import secrets
from models.trusted_device import TrustedDevice, UserTrustedDevice
from extensions import db
from datetime import datetime, timezone

def generate_device_token():
    return secrets.token_urlsafe(32)

def save_trusted_device(user_id, device_token, verified=False):
    """Save or update a device for a user."""
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
    """Mark a device as verified (from email link)."""
    device = TrustedDevice.query.filter_by(device_token=device_token).first()
    if device and not device.verified:
        device.verified = True
        device.verified_at = datetime.now(timezone.utc)
        db.session.commit()

def is_trusted_device(user_id, device_token):
    """Check if device is verified and belongs to user."""
    if not device_token:
        return False
    device = TrustedDevice.query.filter_by(device_token=device_token, verified=True).first()
    if not device:
        return False
    link = UserTrustedDevice.query.filter_by(user_id=user_id, device_id=device.id).first()
    return bool(link)
