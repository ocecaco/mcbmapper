import numpy as np
import json
from PIL import Image
import sys
import msgpack

with open('biomes2.json', 'rb') as f:
    colors = json.load(f)
    colors = {x['id']: x['color'] for x in colors}

filename = sys.argv[1]
contents = msgpack.load(open(filename, 'rb'))
biome_data = np.frombuffer(contents[b'biomes'], dtype=np.uint8).reshape(2000, 2000)


def get_color(b, i):
    c = colors.get(b)
    if c is None:
        print(b)
        return 0

    return c[i]


data_r = np.vectorize(lambda b: get_color(b, 'r'))(biome_data)
data_g = np.vectorize(lambda b: get_color(b, 'g'))(biome_data)
data_b = np.vectorize(lambda b: get_color(b, 'b'))(biome_data)
combined = np.stack([data_r, data_g, data_b], axis=-1)

image = Image.fromarray(combined.astype(np.uint8))
image.save('map.png')
