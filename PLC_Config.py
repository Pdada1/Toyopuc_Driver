""" Class which holds the values for setup of a EIP connection required from the PLC.
In this connection the PLC is assumed as the Originator and other devices are the Target Device
Name: Name of the PLC in order to keep track if multiple objects are created
IP: IP address assigned to the PLC
T:Target, O: Originator
ASSM_RX: The assembly instance assigned to recieve T->O packets
ASSM_TX: The assembly instance assigned to send out O->T packets
ASSM_RX_BYTE_SIZE: The amount of data in bytes that the PLC is expecting to receive T->O
ASSM_TX_BYTE_SIZE: The amount of data in bytes that the PLC is expected to send O->T
"""

"Note on features, will probably want to make this read from a config file and have the PLC class"
"Hold a dictionary with the config of connections"
"Should probably make a connection class with properties for it"
class PLC_Config:    

    def __init__(self, name:str,ip:str, assm_rx:int,assm_tx:int,rx_byte_size:int, tx_byte_size:int) -> None:
       self.name=name
       self.ip=ip
       self.assm_rx=assm_rx
       self.assm_tx=assm_tx
       self.rx_byte_size=rx_byte_size
       self.tx_byte_size=tx_byte_size

    def __str__(self) -> str:
        return "f PLC Name= {self.name}\n" \
        "PLC IP= {self.ip}\n" \
        "The receiving assembly is = {self.assm_rx}\n" \
        "The transmitting assembly is = {self.assem_tx}\n" \
        "The amount of data PLC expects to receive is = {self.rx_byte_size} bytes\n"\
        "The amount of data the PLC will send is = {self.tx_byte_size} bytes\n"\





