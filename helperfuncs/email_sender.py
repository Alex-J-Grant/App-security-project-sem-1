
import os
from flask_mail import Message
from extensions import mail
from helperfuncs.getcountry import country_name_from_code
#takes in the message the receivers email, name,the subject and the type of email we want to send
#optional but also takes in the country or device code for warning about new log ins
def send_email(message_body, rcv_email, name,type,country="",device=""):

    if type == "2FA":
        msg = Message(
            "Your Social Commune 2FA CODE",
            sender=os.getenv("EMAIL"),
            recipients=[rcv_email],
        )
        msg.body = (f"Hello {name}, here is your 2FA code to verify yourself\n\n{message_body}\n\nThis Code expires in 5 minutes\
                    \n\n If you did not request this, please change your password as soon as possible")
        mail.send(msg)


    if type == "warning_new_country":
        print(country)
        if country is None:
            country = "Unknown"
        msg = Message(
            "Social Commune log in attempt at new location",
            sender=os.getenv("EMAIL"),
            recipients=[rcv_email],
        )
        msg.body = (f"Hello {name}, there has been an attempt to log in to your account from a different country ({country_name_from_code(country)})\n\n\
                            \n If this wasn't you, please reset your password.")
        mail.send(msg)

    if type == "forgetpw":
        msg = Message(
            "Social Commune Password Reset",
            sender = os.getenv("Email"),
            recipients = [rcv_email],

        )
        msg.body = (f"Hello {name}, here is your password reset link {message_body}")
        
        mail.send(msg)

    if type == "verify_new_device":

        msg = Message(
            "Social Commune New Device Log In",
            sender = os.getenv("EMAIL"),
            recipients = [rcv_email]
        )
        msg.body = (f"Hello {name}, here is the link to trust a new device to your account \n {message_body}\n\n\
If you did not request this, please change your password as soon as possible.")
        mail.send(msg)