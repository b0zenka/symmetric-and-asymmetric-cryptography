from pydantic import BaseModel

class KeyModel(BaseModel):
    key: str
    
class MessageModel(BaseModel):
    text: str

class DecodeModel(BaseModel):
    text: str

class VerificationMessageModel(BaseModel):
    message: str
    signature: str