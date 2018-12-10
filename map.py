import frida
import sys
import numpy as np

session = frida.get_usb_device().attach("com.mojang.minecraftpe")
session.enable_jit()

with open('map.js') as f:
    script = session.create_script(f.read())

TILE_SIZE = 20

seed = None
x = None
z = None
biomes = None


def on_message(message, data):
    global seed, x, z, biomes
    payload = message['payload']
    message_type = payload['type']

    if message_type == 'seed':
        seed = payload['seed']
        x = payload['x']
        z = payload['z']
        max_i = payload['max_i']
        max_j = payload['max_j']
        biomes = np.zeros((max_j * TILE_SIZE, max_i * TILE_SIZE), dtype=np.uint8)
    elif message_type == 'data':
        i = payload['i']
        j = payload['j']
        arr = np.frombuffer(data, dtype=np.uint32).reshape((TILE_SIZE, TILE_SIZE))
        biomes[j*20:(j+1)*20, i*20:(i+1)*20] = arr
    elif message_type == 'done':
        np.save('data/biomedata_{}_s_{}_{}.bio'.format(seed, x, z), biomes)
        print(seed)
        biomes = None
    else:
        raise RuntimeError('unknown message type')


script.on('message', on_message)
script.load()
sys.stdin.read()
