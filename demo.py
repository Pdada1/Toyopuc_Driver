
from datetime import datetime
from driver import ToyopucDriver
from addressing import Addressing

IP, PORT = "192.168.0.10", 9600
plc = ToyopucDriver(IP, PORT, timeout=3.0, verbose=True)
plc.connect()
print(plc.read_clock())

#Read D0100..D0102
#start = Addressing.d_word_address(0x0FF)
#print (plc.read_d_words(start,3))

#  Read V001
v001 = Addressing.word_address("S", 0x200)
print(plc.read_bytes(v001,10))

print(plc.read_latest_error())

plc.read_error_bits()

plc.close()
