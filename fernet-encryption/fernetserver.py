import urllib.request
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
msg=str(input('Enter your message : '))
password_provided = input("Provide a key : ")
password = password_provided.encode()
salt = b'salt_'
kdf = PBKDF2HMAC(
algorithm=hashes.SHA256(),
length=32,
salt=salt,
iterations=100000,
backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))
urllib.request.urlopen
msg=msg.encode()
f = Fernet(key)
msg=f.encrypt(msg)
msg=str(msg)
print("\nYour encrypted text is: "+msg)
b=urllib.request.urlopen('https://api.thingspeak.com/update?api_key=M0EFAIMXXCZPY7T8&field1='+msg)
print("\nYour message has successfully been sent with end-to-end encryption!\nThe receiver needs to enter the same key.")