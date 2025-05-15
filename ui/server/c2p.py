import mmap
import struct
import posix_ipc
import asyncio
import websockets
import json

SHM_NAME = "/my_shm"
SHM_SIZE = 1024

# Define struct format
smdata_fmt = 'i16s16s10sii26s'
smdata_size = struct.calcsize(smdata_fmt)

print(smdata_size)

# Open and map shared memory
shm = posix_ipc.SharedMemory(SHM_NAME)
mapfile = mmap.mmap(shm.fd, SHM_SIZE)
shm.close_fd()

print("Python listener started, waiting for packets...\n")

async def handler(websocket, path):
    try:
        while True:
            # Wait for status == 1 (packet ready)
            while True:
                mapfile.seek(0)
                status = struct.unpack('i', mapfile.read(4))[0]
                if status == 1:
                    break
                # time.sleep(0.000001)  # Avoid CPU spinning (1 us delay)

            # Read entire smData struct
            mapfile.seek(0)
            data = mapfile.read(smdata_size)
            status, src_ip, dest_ip, prot, src_port, dest_port, time = struct.unpack(smdata_fmt, data)

            # Decode byte strings
            src_ip = src_ip.decode('utf-8', errors='replace').rstrip('\x00')
            dest_ip = dest_ip.decode('utf-8', errors='replace').rstrip('\x00')
            prot = prot.decode('utf-8', errors='replace').rstrip('\x00')
            time = time.decode('utf-8', errors='replace').rstrip('\x00')
            
            data = {
                "time": time,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "prot": prot,
                "src_port": src_port,
                "dest_port": dest_port
            }

            await websocket.send(json.dumps(data))

            # Display received packet info
            print(f"[RECEIVED] Status={status} | Src={src_ip} | Dest={dest_ip} | Protocol={prot} | src_port={src_port} | dest_port={dest_port} | time={time}")

            # Reset status to 0 (ready for next)
            mapfile.seek(0)
            mapfile.write(struct.pack('i', 0))
            mapfile.flush()

    except KeyboardInterrupt:
        print("\nExiting gracefully.")
    finally:
        mapfile.close()

async def main():
    async with websockets.serve(handler, "10.0.0.100", 8081):
        print("WebSocket server started on ws://10.0.0.100:8081")
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())

# try:
#     while True:
#         # Wait for status == 1 (packet ready)
#         while True:
#             mapfile.seek(0)
#             status = struct.unpack('i', mapfile.read(4))[0]
#             if status == 1:
#                 break
#             # time.sleep(0.000001)  # Avoid CPU spinning (1 us delay)

#         # Read entire smData struct
#         mapfile.seek(0)
#         data = mapfile.read(smdata_size)
#         status, src_ip, dest_ip, prot, src_port, dest_port, time = struct.unpack(smdata_fmt, data)

#         # Decode byte strings
#         src_ip = src_ip.decode('utf-8', errors='replace').rstrip('\x00')
#         dest_ip = dest_ip.decode('utf-8', errors='replace').rstrip('\x00')
#         prot = prot.decode('utf-8', errors='replace').rstrip('\x00')
#         time = time.decode('utf-8', errors='replace').rstrip('\x00')
        

#         # Display received packet info
#         print(f"[RECEIVED] Status={status} | Src={src_ip} | Dest={dest_ip} | Protocol={prot} | src_port={src_port} | dest_port={dest_port} | time={time}")

#         # Reset status to 0 (ready for next)
#         mapfile.seek(0)
#         mapfile.write(struct.pack('i', 0))
#         mapfile.flush()

# except KeyboardInterrupt:
#     print("\nExiting gracefully.")
# finally:
#     mapfile.close()