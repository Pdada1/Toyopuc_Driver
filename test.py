import socket
from PLC_Config import PLC_Config
s=PLC_Config("Test","192.168.0.37",100,101,10,10)
print(s)

hostname = socket.gethostname()
IPAddr = socket.gethostbyname(socket.gethostname())
