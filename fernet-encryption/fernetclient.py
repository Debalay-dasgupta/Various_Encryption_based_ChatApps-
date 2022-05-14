import requests
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
msg=requests.get("https://thingspeak.com/channels/1461170/field/1")
msg=msg.json()['feeds'][-1]['field1']
password_provided = input("Provide the key : ")
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
f=Fernet(key)
print("\nEncrypted text you've received :\n\n"+msg)
try:
	msg=msg[2:-1]
	msg=bytes(msg,'utf-8')
	msg=f.decrypt(msg)
	print("\nThe Message sent was: \n\n"+str(msg)[2:-1])
except:
	print("\nWrong key can't display msg\n")