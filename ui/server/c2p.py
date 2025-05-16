import mmap
import struct
import posix_ipc
import asyncio
import websockets
import json

SHM_NAME = "/my_shm"
SHM_SIZE = 1024

# Define struct format
smdata_fmt = 'i46s46s10sii26si'
smdata_size = struct.calcsize(smdata_fmt)

print("Python listener started, waiting for packets...\n")

connected_clients = set()

async def producer():
    shm = posix_ipc.SharedMemory(SHM_NAME)
    mapfile = mmap.mmap(shm.fd, SHM_SIZE)
    shm.close_fd()

    print("Reading from shared memory...")

    try:
        while True:
            mapfile.seek(0)
            status = struct.unpack('i', mapfile.read(4))[0]
            if status != 1:
                await asyncio.sleep(0.001)
                continue

            mapfile.seek(0)
            data = mapfile.read(smdata_size)
            status, src_ip, dest_ip, prot, src_port, dest_port, time, ethType = struct.unpack(smdata_fmt, data)

            src_ip = src_ip.decode('utf-8', errors='replace').rstrip('\x00')
            dest_ip = dest_ip.decode('utf-8', errors='replace').rstrip('\x00')
            prot = prot.decode('utf-8', errors='replace').rstrip('\x00')
            time = time.decode('utf-8', errors='replace').rstrip('\x00')

            packet_data = {
                "time": time,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "prot": prot,
                "src_port": src_port,
                "dest_port": dest_port
            }

            print(f"[RECEIVED] Src={src_ip} | Dest={dest_ip} | Protocol={prot} | src_port={src_port} | dest_port={dest_port} | time={time}")

            # Reset status
            mapfile.seek(0)
            mapfile.write(struct.pack('i', 0))
            mapfile.flush()

            # Broadcast to all clients
            await broadcast(json.dumps(packet_data))

    finally:
        mapfile.close()

async def broadcast(message):
    disconnected = set()
    for ws in connected_clients:
        try:
            await ws.send(message)
        except:
            disconnected.add(ws)
    for ws in disconnected:
        connected_clients.remove(ws)

async def handler(websocket):
    print("Client connected.")
    connected_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.remove(websocket)
        print("Client disconnected.")

async def main():
    server = await websockets.serve(handler, "0.0.0.0", 8081)
    print("WebSocket server listening on ws://0.0.0.0:8081")
    await producer()  # Runs forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Fatal server error: {e}")

# async def handler(websocket):
#     try:
#         shm = posix_ipc.SharedMemory(SHM_NAME)
#         mapfile = mmap.mmap(shm.fd, SHM_SIZE)
#         shm.close_fd()

#         while True:
#             # Wait for status == 1 (packet ready)
#             while True:
#                 mapfile.seek(0)
#                 status = struct.unpack('i', mapfile.read(4))[0]
#                 if status == 1:
#                     break
#                 # await asyncio.sleep(0.000001)

#             # Read entire smData struct
#             mapfile.seek(0)
#             data = mapfile.read(smdata_size)
#             status, src_ip, dest_ip, prot, src_port, dest_port, time, ethType = struct.unpack(smdata_fmt, data)

#             # ethType = IPv4
#             if ethType == 0:
#                 src_ip = src_ip.decode('utf-8', errors='replace')[:16].rstrip('\x00')
#                 dest_ip = dest_ip.decode('utf-8', errors='replace')[:16].rstrip('\x00')

#             # ethType = IPv6
#             elif ethType == 1:
#                 src_ip = src_ip.decode('ascii', errors='replace').rstrip('\x00')
#                 dest_ip = dest_ip.decode('ascii', errors='replace').rstrip('\x00')

#             # Decode byte strings
#             prot = prot.decode('utf-8', errors='replace').rstrip('\x00')
#             time = time.decode('utf-8', errors='replace').rstrip('\x00')
            
#             data = {
#                 "time": time,
#                 "src_ip": src_ip,
#                 "dest_ip": dest_ip,
#                 "prot": prot,
#                 "src_port": src_port,
#                 "dest_port": dest_port
#             }
            
#             # Display received packet info
#             print(f"[RECEIVED] Src={src_ip} | Dest={dest_ip} | Protocol={prot} | src_port={src_port} | dest_port={dest_port} | time={time} | ethType={ethType}")

#             # Reset status to 0 (ready for next)
#             mapfile.seek(0)
#             mapfile.write(struct.pack('i', 0))
#             mapfile.flush()

#             await websocket.send(json.dumps(data))

#     except Exception as e:
#         print(f"Handler error: {e}")
#         raise
#     finally:
#         mapfile.close()

# async def main():
#     async with websockets.serve(handler, "0.0.0.0", 8081):
#         print("WebSocket server started on ws://0.0.0.0:8081")
#         await asyncio.Future()  # Run forever

# if __name__ == "__main__":
#     try:
#         asyncio.run(main())
#     except Exception as e:
#         print(f"Server failed to start: {e}")

# try:
#     shm = posix_ipc.SharedMemory(SHM_NAME)
#     mapfile = mmap.mmap(shm.fd, SHM_SIZE)
#     shm.close_fd()

#     while True:
#         # Wait for status == 1 (packet ready)
#         while True:
#             mapfile.seek(0)
#             status = struct.unpack('i', mapfile.read(4))[0]
#             if status == 1:
#                 break
#             # await asyncio.sleep(0.000001)

#         # Read entire smData struct
#         mapfile.seek(0)
#         data = mapfile.read(smdata_size)
#         status, src_ip, dest_ip, prot, src_port, dest_port, time, ethType = struct.unpack(smdata_fmt, data)

#         # ethType = IPv4
#         if ethType == 0:
#             src_ip = src_ip.decode('utf-8', errors='replace')[:16].rstrip('\x00')
#             dest_ip = dest_ip.decode('utf-8', errors='replace')[:16].rstrip('\x00')

#         # ethType = IPv6
#         elif ethType == 1:
#             src_ip = src_ip.decode('utf-8', errors='replace').rstrip('\x00')
#             dest_ip = dest_ip.decode('utf-8', errors='replace').rstrip('\x00')

#         # Decode byte strings
#         prot = prot.decode('utf-8', errors='replace').rstrip('\x00')
#         time = time.decode('utf-8', errors='replace').rstrip('\x00')
        
#         data = {
#             "time": time,
#             "src_ip": src_ip,
#             "dest_ip": dest_ip,
#             "prot": prot,
#             "src_port": src_port,
#             "dest_port": dest_port
#         }
        
#         # Display received packet info
#         print(f"[RECEIVED] Src={src_ip} | Dest={dest_ip} | Protocol={prot} | src_port={src_port} | dest_port={dest_port} | time={time} | ethType={ethType}")

#         # Reset status to 0 (ready for next)
#         mapfile.seek(0)
#         mapfile.write(struct.pack('i', 0))
#         mapfile.flush()

# except Exception as e:
#     print(f"Handler error: {e}")
#     raise
# finally:
#     mapfile.close()