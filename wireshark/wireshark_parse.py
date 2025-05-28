import pyshark

commandIndex = 6
subCommandIndex = 0

cmdNames = {
    0x01 : "Acquisition Time Setting - LSB",
    0x02 : "Bias Setting",
    0x03 : "Acquisition Start",
    0x04 : "Internal DAC Settings",
    0x05 : "Seq. Readout Start",
    0x06 : "Seq. Readout Start",
    0x07 : "HW Command Start",
    0x08 : "Sensor Register Setting",
    0x09 : "Acquisition Mode Setting",
    0x0A : "Acquisition Time Setting - MSB",
    0x0B : "Echo Chip ID",
    0x0C : "Get Bias Voltage",
    0x0D : "Get ADC Voltage",
    0x0E : "Get Back Read Register",
    0x0F : "Internal DAC Scan",
    0x10 : "Set Pixel Config",
    0x11 : "Get Pixel Config",
    0x12 : "Sett All Pixel Config",
    0x13 : "Number of Frames Setting",
    0x14 : "Get All DAC Scan",
    0x15 : "Get HW/Readout Temperature",
    0x16 : "LED settings",
    0x17 : "Get Readout Status",
    0x18 : "Get Communication Status",
    0x19 : "Get Sensor Temperature",
    0x20 : "Digital Test",
    0x21 : "Acquisition Setup",
    0x28 : "HW ToA Compensation Setup",
    0x29 : "Set the number of tokens",
    0x23 : "InternalTriggerGenerator - v2",
    0x32 : "InternalTDCSettings - v2"
}

valid_ports = {'1556','62510'}

def process_data_packet(f,raw, msgNum):
    if (len(raw) < 6):
        print("Unexpected length while processing subpackets")

    command = (raw[5] & 0b11110000) >> 4
    f.write(f"\tCMD({msgNum}): 0x{command:x}\n")


    if (len(raw) > 6):    
        process_data_packet(f,raw[6:],msgNum+1)



def filter_and_print_measurement_info(pcapng_file, target_ip):
    # Only load layers necessary to speed up parsing
    cap = pyshark.FileCapture(
        pcapng_file,
        display_filter=f"ip.addr == {target_ip}",
        use_json=True,
        include_raw=True
    )

    outputfile = pcapng_file[:pcapng_file.index(".")]+"_measurment_parsed.txt"
    with open(outputfile, "w" ,encoding='utf-8') as f:
        packetCounts = {}
        for packet in cap:
            try:
                # check if its a data packet
                if not hasattr(packet,'data'):
                    continue

                # check that its coming from the data port
                port = packet.udp.srcport
                if port not in valid_ports:
                    continue
                
                
                raw = bytes.fromhex(packet.data.data.replace(':', ''))
                if(len(raw)<6):
                    print("Unexpected length")
                    print(f"Payload (hex): {' '.join(f'{b:02x}' for b in raw)}\n")
                    print("")
                    continue
                             
                command = (raw[5] & 0b11110000) >> 4
            
                f.write(f"Packet #{packet.number}\n")
                f.write(f"From port: {port}\n")
                f.write(f"Length: {len(raw)} -> num msgs = {(len(raw)/6)}\n")
                f.write("\tCMD(1): 0x%x\n" % command)

                if(len(raw)>6):
                    process_data_packet(f,raw[6:],2)
                

                f.write("-" * 50)
                f.write("\n")
                f.flush()
            except AttributeError as e:
                print(f"ERROR: {e}")
                continue
        
        for k,v in packetCounts.items():
            commandDescription = "Unknown"
            if k in cmdNames:
                commandDescription = cmdNames[k]
            f.write("CMD: 0x%02x (%-35s) - %5i usages\n" % (k, commandDescription, v/2)) # /2 for cmd-rsp pairs

        f.flush()
        cap.close()

def filter_and_print_data(pcapng_file, target_ip):
    # Only load layers necessary to speed up parsing
    cap = pyshark.FileCapture(
        pcapng_file,
        display_filter=f"ip.addr == {target_ip}",
        use_json=True,
        include_raw=True
    )

    outputfile = pcapng_file[:pcapng_file.index(".")]+"_parsed.txt"
    with open(outputfile, "w" ,encoding='utf-8') as f:
        packetCounts = {}
        for packet in cap:
            try:
                # check if its a data packet
                if not hasattr(packet,'data'):
                    continue

                # check that is a valid data packet for a command
                raw = bytes.fromhex(packet.data.data.replace(':', ''))
                if(len(raw)!=8):
                    print("Unexpected length")
                    print(f"Payload (hex): {' '.join(f'{b:02x}' for b in raw)}\n")
                    print("")
                    continue
                             
                command = raw[commandIndex]
                # keep track of command counts
                if int(command) not in packetCounts:
                        packetCounts[command] = 0
                packetCounts[command] = packetCounts[command] + 1

                # dont print checks we dont care about
                if command == 0x0c or command == 0x15 or command == 0x19:
                    continue

                src = packet.ip.src
                dst = packet.ip.dst
                length = packet.length
            
                f.write(f"Packet #{packet.number}\n")
                f.write(f"Source: {src}, Destination: {dst}\n")
                f.write(f"Length: {length}\n")
                f.write(f"Payload (hex): {' '.join(f'{b:02x}' for b in raw)}\n")
                f.write("\tCMD: 0x%02x\n" % command)
                if(command == 0x07):
                    f.write("\tsubCmd: 0x%02x\n" % raw[subCommandIndex])   

                f.write("-" * 50)
                f.write("\n")
                f.flush()
            except AttributeError as e:
                print(f"ERROR: {e}")
                continue
        
        for k,v in packetCounts.items():
            commandDescription = "Unknown"
            if k in cmdNames:
                commandDescription = cmdNames[k]
            f.write("CMD: 0x%02x (%-35s) - %5i usages\n" % (k, commandDescription, v/2)) # /2 for cmd-rsp pairs

        f.flush()
        cap.close()

# Example usage
# filter_and_print_data('wireshark_tracklab.pcapng', '192.168.1.3')
filter_and_print_measurement_info('wireshark_manual_2.pcapng', '192.168.1.3')
