import pyshark

commandIndex = 6
subCommandIndex = 7

def filter_and_print_data(pcapng_file, target_ip):
    # Only load layers necessary to speed up parsing
    cap = pyshark.FileCapture(
        pcapng_file,
        display_filter=f"ip.addr == {target_ip}",
        use_json=True,
        include_raw=True
    )


    with open("filtered_out.txt", "w" ,encoding='utf-8') as f:
        for packet in cap:
            try:
                # check if its a data packet
                if not hasattr(packet,'data'):
                    continue

                # check that is a valid data packet for a command
                raw = bytes.fromhex(packet.data.data.replace(':', ''))
                if(len(raw)!=8):
                    print("Unexpected length")
                    continue

                # do we care about it
                command = raw[commandIndex]
                if command == 0x0c or command == 0x15 or command == 0x19:
                    continue

                src = packet.ip.src
                dst = packet.ip.dst
                length = packet.length
            
                f.write(f"Packet #{packet.number}\n")
                f.write(f"Source: {src}, Destination: {dst}\n")
                f.write(f"Length: {length}\n")
                f.write(f"Payload (hex): {raw.hex()}\n")
                f.write("\tCMD: ox%02x\n" % command)
                if(command == 0x07):
                    f.write("\tsubCmd: ox%02x\n" % raw[subCommandIndex])   

                f.write("-" * 50)
                f.write("\n")
                f.flush()
            except AttributeError as e:
                print(f"ERROR: {e}")
                continue

        cap.close()

# Example usage
filter_and_print_data('timepix_data_tracklab_1010.pcapng', '192.168.1.3')
