import binascii
from typing import Dict

from fastapi import FastAPI, HTTPException
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from helpers import is_hex

from models import DecodeModel, MessageModel, KeyModel, VerificationMessageModel

symetric_key = None
asymetric_private_key = None
asymetric_public_key = None

app = FastAPI()

#region Symetric key

@app.get("/symetric/key", tags=["Symetric key methods"])
async def generate_symetric_key():
    """_Generate and returns a randomly symetric key in HEX form_

    Returns:
        key (str): _key in HEX form_
    """
    key = Fernet.generate_key()
    return { "key": key.hex() }

@app.post("/symetric/key", tags=["Symetric key methods"])
def symetric_key(model: KeyModel):
    """_Sets the symmetric key given in HEX form on the server_

    Args:
        model (KeyModel): _model consists of a symmetric hex key_

    Returns:
        message (str): _result message_
    """
    global symetric_key
    
    if not model.key:
        raise HTTPException(status_code = 400, detail = "Given key is empty.")
    
    if not is_hex(model.key):
        raise HTTPException(status_code = 400, detail = "Given key is not in hex form.")
    
    symetric_key = model.key
    return { "message": "Symmetric key set successfully." }

@app.post("/symetric/encode", tags=["Symetric key methods"])
def symetric_encode(model: MessageModel):
    """_Encrypts the sent message_

    Args:
        model (MessageModel): _model consists of a message to encrypt_

    Returns:
        encrypted (str): _encrypted message_
    """
    global symetric_key
    if not symetric_key:
        raise HTTPException(status_code = 400, detail = "Symetric key is empty.")
    if not is_hex(symetric_key):
        raise HTTPException(status_code = 400, detail = "Given key is not in hex form.")
    
    key_bytes = binascii.unhexlify(symetric_key)
    f = Fernet(key_bytes)
    return { "encrypted": f.encrypt(model.text.encode()) }

@app.post("/symetric/decode", tags=["Symetric key methods"])
def symetric_decode(model: MessageModel):
    """_Decrypts the sent message_

    Args:
        model (MessageModel): _model consists of a message to decrypt_

    Returns:
        decrypted (str): _decrypted message_
    """
    global symetric_key
    if not symetric_key:
        raise HTTPException(status_code = 400, detail = "Symetric key is empty.")
    if not is_hex(symetric_key):
        raise HTTPException(status_code = 400, detail = "Given key is not in hex form.")
    
    key_bytes = binascii.unhexlify(symetric_key)
    f = Fernet(key_bytes)
    decrypted = f.decrypt(model.text)
    return { "decrypted": decrypted.decode() }

#endregion

#region Asymetric key

@app.get("/asymetric/key", tags=["Asymetric key methods"])
def asymetric_generate_key():
    """_Generate and returns an asymetric symetric key in HEX form_

    Returns:
        private_key: _private key in hex_, 
        public_key: _public key in hex_
    """
    global asymetric_private_key, asymetric_public_key
    asymetric_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    asymetric_public_key = asymetric_private_key.public_key()
    
    private_key_pem = asymetric_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key_pem = asymetric_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return {"private_key": private_key_pem.hex(), "public_key": public_key_pem.hex()}

@app.get("/asymetric/key/ssh", tags=["Asymetric key methods"])
def asymetric_key_ssh():
    """_Generate and returns an asymetric symetric key in HEX form in OpenSSH format_

    Returns:
        private_key: _private key in hex_, 
        public_key: _public key in hex_
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return {"private_key": private_pem.hex(), "public_key": public_pem.hex()}

@app.post("/asymetric/key", tags=["Asymetric key methods"])
def asymetric_key(keys: Dict[str, str]):
    """_Sets the public and private keys in HEX on the server_

    Args:
        keys (Dict[str, str]): _dict private_key, public_key_

    Returns:
        message (str): _result message_
    """
    global asymetric_private_key, asymetric_public_key
    try:
        asymetric_private_key = serialization.load_pem_private_key(
            binascii.unhexlify(keys['private_key']),
            password=None
        )
        asymetric_public_key = serialization.load_pem_public_key(
            binascii.unhexlify(keys['public_key']),
        )
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return { "message": "The public and private keys have been set." }

@app.post("/asymetric/sign", tags=["Asymetric key methods"])
def asymetric_sign(model: MessageModel):
    """_Uses the currently set private key to sign the given message and returns the signed message_

    Args:
        model (MessageModel): _message to sign_

    Returns:
       message (str): _message in hex_, 
       signature (str): _signature in hex_
    """
    global asymetric_private_key
    if asymetric_private_key is None:
        raise HTTPException(status_code = 400, detail = "No private key set on server.")
    
    message = model.text.encode()
    signature = asymetric_private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return { "message": message.hex(), "signature": signature.hex() }

@app.post("/asymetric/verify", tags=["Asymetric key methods"])
def asymetric_verify(model: VerificationMessageModel):
    """_Using the currently set public key method verify whether the message was signed using it_

    Args:
        model (VerificationMessageModel): _message (str), signature (str)_

    Returns:
        result (str): _result message_
    """
    global asymetric_public_key
    
    if asymetric_public_key is None:
        raise HTTPException(status_code = 400, detail = "No public key set on server.")
    
    if not model.signature or not model.message:
        raise HTTPException(status_code=400, detail="Both message and signature are required")
    
    try:
        asymetric_public_key.verify(
            binascii.unhexlify(model.signature),
            binascii.unhexlify(model.message),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return {"result": "Signature is valid"}

@app.post("/asymetric/encode", tags=["Asymetric key methods"])
def asymetric_encode(model: MessageModel):
    """_Encrypts the sent message_

    Args:
        model (MessageModel): _model consists of a message to encrypt_

    Returns:
        encrypted_message (str): _encrypted message in hex_
    """
    global asymetric_public_key
    
    if asymetric_public_key is None:
        raise HTTPException(status_code = 400, detail = "No public key set on server.")
    
    encrypted = asymetric_public_key.encrypt(
        model.text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return { "encrypted_message": encrypted.hex() }

@app.post("/asymetric/decode", tags=["Asymetric key methods"])
def asymetric_decode(model: DecodeModel):
    """_Decrypts the sent message_

    Args:
        model (DecodeModel): _model consists of a message to decrypt in hex_

    Returns:
        decrypted_message (str): _decrypted message_
    """
    global asymetric_private_key
    if asymetric_private_key is None:
        raise HTTPException(status_code = 400, detail = "No private key set on server.")
    
    decrypted_message = asymetric_private_key.decrypt(
        binascii.unhexlify(model.text),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return { "decrypted_message": decrypted_message }

#endregion