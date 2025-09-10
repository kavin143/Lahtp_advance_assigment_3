# create_secret_key.py
from cryptography.fernet import Fernet

# TO GENRATE A SECRET KEY FOR SAFE CLIENT MESSAGE 
# STORE IN SECRET.KEY 
# FOR TESTING I AM PLACE A SECRET KEY IN THE SAME FILE 
# SECURITY PUPROSE THIS WANT PLACE IN SEPRATE PRODUCTED SPACE 
if __name__ == "__main__":
    key = Fernet.generate_key()
    with open("secret.key", "wb") as f:
        f.write(key)
    print("secret.key created")
