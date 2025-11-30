from pydantic import BaseModel

class SSHLog(BaseModel):
    ip: str
    user: str
    status: str
    timestamp: str
