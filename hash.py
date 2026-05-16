import hashlib

password = "invest123"
hashed = hashlib.sha256(password.encode()).hexdigest()
print(hashed)
