"use strict";
function getExportMapping(module) {
    var exports = Module.enumerateExportsSync(module);

    var exportsMapping = {};
    for (var i = 0; i < exports.length; i++) {
        exportsMapping[exports[i].name] = exports[i].address;
    }

    function getAddress(exportName) {
        return exportsMapping[exportName];
    }

    return getAddress;
}

var module = 'libminecraftpe.so';
var baseAddress = Module.findBaseAddress(module);
var getAddress = getExportMapping(module);
var biomePlains = Memory.readPointer(baseAddress.add(new NativePointer("0x3267358"))); // Biomes::mPlains

var BIOME_TILE_SIZE = 20;

var biomeSourceConstructor = new NativeFunction(getAddress('_ZN11BiomeSourceC2EjR5BiomeSt10shared_ptrI5LayerES4_'),
                                                'void',
                                                ['pointer',
                                                 'int32',
                                                 'pointer',
                                                 ['pointer', 'pointer'],
                                                 ['pointer', 'pointer']]);

var createDefaultLayers = new NativeFunction(getAddress('_ZN18OverworldDimension19createDefaultLayersExRSt10shared_ptrI5LayerES3_13GeneratorTypeb'),
                                             'void',
                                             ['int64', 'pointer', 'pointer', 'int32', 'uint32']);

// var getSpawn =
//     new NativeFunction(getAddress('_ZNK11BiomeSource16getSpawnPositionEv'),
//                        'void', ['pointer', 'pointer']);

var fillArea =
    new NativeFunction(getAddress('_ZN15OceanMixerLayer8fillAreaER9LayerDataiiii'),
                       'void', ['pointer', 'pointer', 'int', 'int', 'int', 'int']);

function allocLayerData(size) {
    let layerData = Memory.alloc(8 + size);
    let left = layerData.add(8);
    let right = layerData.add(8 + size / 2);
    Memory.writePointer(layerData, left);
    Memory.writePointer(layerData.add(4), right);
    return layerData;
}

function createSourceAndLayers(seed) {
    var layer1 = Memory.alloc(8);
    var layer2 = Memory.alloc(8);
    createDefaultLayers(seed, layer1, layer2, 1, 0);
    var source = Memory.alloc(8192);
    biomeSourceConstructor(source, seed, biomePlains, [Memory.readPointer(layer1), Memory.readPointer(layer1.add(4))], [Memory.readPointer(layer2), Memory.readPointer(layer2.add(4))]);

    return {
        biomeSource: source,
        layer1full: layer1,
        layer2full: layer2,
        layer1: Memory.readPointer(layer1),
        layer2: Memory.readPointer(layer2)
    };
}

// // var setupChunkSeedA = getAddress('_ZN12LargeFeature14setupChunkSeedEjR6Randomii');
// // var setupChunkSeed = new NativeFunction(setupChunkSeedA, 'void', ['int', 'pointer', 'int', 'int']);

// // var isFeatureChunkA = getAddress('_ZN14VillageFeature14isFeatureChunkEP11BiomeSourceR6RandomRK8ChunkPos');
// // var isFeatureChunk = new NativeFunction(isFeatureChunkA, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);

// // var isFeatureChunkA = getAddress('_ZN16MineshaftFeature14isFeatureChunkEP11BiomeSourceR6RandomRK8ChunkPos');
// // var isFeatureChunk = new NativeFunction(isFeatureChunkA, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);

// // var VillageFeatureA = getAddress('_ZN14VillageFeatureC2Ej');
// // var VillageFeature = new NativeFunction(VillageFeatureA, 'void', ['pointer', 'int']);

// // var VillageFeatureA = getAddress('_ZN16StructureFeatureC2Ej');
// // var VillageFeature = new NativeFunction(VillageFeatureA, 'void', ['pointer', 'int']);

// function createBiomeSource(seed) {
//     var mem = Memory.alloc(128);
//     biomeSourceConstructor(mem, seed, 1, 0);
//     getSpawn(mem.add(52), mem);
//     return mem;
// }

// function layerFromBiomeSource(source) {
//     return Memory.readPointer(source.add(4));
// }

// function spawnPosition(source) {
//     var spawnX = Memory.readS32(source.add(52));
//     var spawnZ = Memory.readS32(source.add(60));
//     return [spawnX, spawnZ];
// }

function getBiomes(layer, layerData, x, z) {
    fillArea(layer, layerData, x, z, BIOME_TILE_SIZE, BIOME_TILE_SIZE);
    var data = Memory.readPointer(layerData);
    var biomes = Memory.readByteArray(data, BIOME_TILE_SIZE * BIOME_TILE_SIZE * 4);
    return biomes;
}

function sendSeedData(layerData, seed) {
    var stuff = createSourceAndLayers(seed);
    var source = stuff.biomeSource;
    var spawn = [0, 0];
    var layer = stuff.layer1;

    var radius = 50;

    var x = Math.round(spawn[0] / 4) - radius * BIOME_TILE_SIZE;
    var z = Math.round(spawn[1] / 4) - radius * BIOME_TILE_SIZE;

    var maxI = radius * 2;
    var maxJ = radius * 2;

    send({'type': 'seed', 'seed': seed, 'x': x, 'z': z, 'max_i': maxI, 'max_j': maxJ});

    for (var i = 0; i < maxI; i++) {
        for (var j = 0; j < maxJ; j++) {
            var biomes = getBiomes(layer, layerData,
                                   x + i * BIOME_TILE_SIZE, z + j * BIOME_TILE_SIZE);
            send({'type': 'data', 'i': i, 'j': j}, biomes);
        }
    }

    send({'type': 'done'})
}

// function main() {
//     console.log('start');


//     // var source = createBiomeSource(seed);
//     // VillageFeature(feature, seed);
//     // for (var i = -250; i <= 250; i++) {
//     //     for (var j = -250; j <= 250; j++) {
//     //         setupChunkSeed(seed, random, i, j);
//     //         Memory.writeS32(pos, i);
//     //         Memory.writeS32(pos.add(4), j); // maybe swap
//     //         var isVillage = isFeatureChunk(feature, source, random, pos);
//     //         if (isVillage === 1) {
//     //             console.log('' + i * 16 + ' ' + j * 16);
//     //         }
//     //     }
//     // }

//     for (var seed = 60000; seed < 70000; seed++) {
//         sendSeedData(layerData, seed);
//     }

//     console.log('stop');
// }
function intercept() {
    var addr = getAddress('_ZN11BiomeSourceC2EjR5BiomeSt10shared_ptrI5LayerES4_');
    Interceptor.attach(addr, {
        onEnter: function (args) {
            console.log(Memory.readPointer());
            console.log('foo: ' + args[2]);
        }
    });
}

function main() {
    var layerData = allocLayerData(1000000);
    var seed = 37286;
    sendSeedData(layerData, seed);
}

setTimeout(main, 500);
console.log('hook');
