
import os
from flask_mail import Message
from extensions import mail

#takes in the message the receivers email, name,the subject and the type of email we want to send
#optional but also takes in the country or device code for warning about new log ins
def send_email(message_body, rcv_email, name,type,country="",device=""):

    if type == "2FA":
        msg = Message(
            "Your Social Commune 2FA CODE",
            sender=os.getenv("EMAIL"),
            recipients=[rcv_email],
        )
        msg.body = (f"Hello {name}, here is your 2FA code to verify yourself\n\n{message_body}\n\nThis Code expires in 3 minutes\
                    \n\n If you didn't request this, please reset your password.")
        mail.send(msg)

    if type == "warning_new_device":
        msg = Message(
            "Social Commune log in attempt on new device",
            sender=os.getenv("EMAIL"),
            recipients=[rcv_email],
        )
        msg.body = (f"Hello {name}, there has been an attempt to log in to your account on a new device ({device})\n\n\
                            \n\n If this wasn't you, please reset your password.")
        mail.send(msg)

    if type == "warning_new_country":
        msg = Message(
            "Social Commune log in attempt at new location",
            sender=os.getenv("EMAIL"),
            recipients=[rcv_email],
        )
        msg.body = (f"Hello {name}, there has been an attempt to log in to your account from a different country ({country})\n\n\
                            \n\n If this wasn't you, please reset your password.")
        mail.send(msg)

