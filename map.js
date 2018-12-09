"use strict";
var BIOME_TILE_SIZE = 20;

var test = getAddress('_ZN11BiomeSourceC2Ej13GeneratorTypeb');
console.log(test);

var biomeSourceConstructor =
    new NativeFunction(getAddress('_ZN11BiomeSourceC2Ej13GeneratorTypeb'),
                       'void', ['pointer', 'int', 'uint', 'int']);

var getSpawn =
    new NativeFunction(getAddress('_ZNK11BiomeSource16getSpawnPositionEv'),
                       'void', ['pointer', 'pointer']);

var fillArea =
    // new NativeFunction(getAddress('_ZN15RiverMixerLayer8fillAreaER9LayerDataiiii'),
    new NativeFunction(getAddress('_ZN15OceanMixerLayer8fillAreaER9LayerDataiiii'),
                       'void', ['pointer', 'pointer', 'int', 'int', 'int', 'int']);

var setupChunkSeedA = getAddress('_ZN12LargeFeature14setupChunkSeedEjR6Randomii');
var setupChunkSeed = new NativeFunction(setupChunkSeedA, 'void', ['int', 'pointer', 'int', 'int']);
// var isFeatureChunkA = getAddress('_ZN14VillageFeature14isFeatureChunkEP11BiomeSourceR6RandomRK8ChunkPos');
// var isFeatureChunk = new NativeFunction(isFeatureChunkA, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
var isFeatureChunkA = getAddress('_ZN16MineshaftFeature14isFeatureChunkEP11BiomeSourceR6RandomRK8ChunkPos');
var isFeatureChunk = new NativeFunction(isFeatureChunkA, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
// var VillageFeatureA = getAddress('_ZN14VillageFeatureC2Ej');
// var VillageFeature = new NativeFunction(VillageFeatureA, 'void', ['pointer', 'int']);
var VillageFeatureA = getAddress('_ZN16StructureFeatureC2Ej');
var VillageFeature = new NativeFunction(VillageFeatureA, 'void', ['pointer', 'int']);

function createBiomeSource(seed) {
    var mem = Memory.alloc(128);
    biomeSourceConstructor(mem, seed, 1, 0);
    getSpawn(mem.add(52), mem);
    return mem;
}

function layerFromBiomeSource(source) {
    return Memory.readPointer(source.add(4));
}

function spawnPosition(source) {
    var spawnX = Memory.readS32(source.add(52));
    var spawnZ = Memory.readS32(source.add(60));
    return [spawnX, spawnZ];
}

// 4608

function getBiomes(layer, layerData, x, z) {
    fillArea(layer, layerData, x, z, BIOME_TILE_SIZE, BIOME_TILE_SIZE);
    var data = Memory.readPointer(layerData);
    var biomes = Memory.readByteArray(data, BIOME_TILE_SIZE * BIOME_TILE_SIZE * 4);
    return biomes;
}

// function testSeed(layerData, seed) {
//     var source = createBiomeSource(seed);
//     var spawn = spawnPosition(source);
//     var riverMixerLayer = layerFromBiomeSource(source);

//     var radius = 50;

//     var x = Math.round(spawn[0] / 4) - radius * BIOME_TILE_SIZE;
//     var z = Math.round(spawn[1] / 4) - radius * BIOME_TILE_SIZE;

//     var maxI = radius * 2;
//     var maxJ = radius * 2;

//     send({'type': 'seed', 'seed': seed, 'x': x, 'z': z, 'max_i': maxI, 'max_j': maxJ});

//     for (var i = 0; i < maxI; i++) {
//         for (var j = 0; j < maxJ; j++) {
//             var biomes = getBiomes(riverMixerLayer, layerData,
//                                    x + i * BIOME_TILE_SIZE, z + j * BIOME_TILE_SIZE);
//             send({'type': 'data', 'i': i, 'j': j}, biomes);
//         }
//     }

//     send({'type': 'done'})
// }

function main2() {
    var layerData = allocLayerData(1000000);
    console.log('start');
    var seed = 37286;
    var source = createBiomeSource(seed);
    VillageFeature(feature, seed);
    for (var i = -250; i <= 250; i++) {
        for (var j = -250; j <= 250; j++) {
            setupChunkSeed(seed, random, i, j);
            Memory.writeS32(pos, i);
            Memory.writeS32(pos.add(4), j); // maybe swap
            var isVillage = isFeatureChunk(feature, source, random, pos);
            if (isVillage === 1) {
                console.log('' + i * 16 + ' ' + j * 16);
            }
        }
    }
    console.log('stop');
}

setTimeout(main2, 500);
console.log('hook');
