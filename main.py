import msgpack

with open("./logs/packets00.msgpack", "rb") as f:
    unpacker = msgpack.Unpacker(f, raw=False)
    for obj in unpacker:
        print(obj)