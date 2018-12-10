"use strict";
function getExportMapping(module) {
    var exports = Module.enumerateExportsSync(module);

    var exportsMapping = {};
    for (var i = 0; i < exports.length; i++) {
        exportsMapping[exports[i].name] = exports[i].address;
    }

    function getAddress(exportName) {
        if (exportsMapping.hasOwnProperty(exportName)) {
            return exportsMapping[exportName];
        } else {
            throw "address not found for name " + exportName;
        }
    }

    return getAddress;
}

var module = 'libminecraftpe.so';
var baseAddress = Module.findBaseAddress(module);
var getAddress = getExportMapping(module);
var biomePlains = Memory.readPointer(getAddress('_ZN13VanillaBiomes7mPlainsE'));

var BIOME_TILE_SIZE = 20;

var biomeSourceConstructor = new NativeFunction(getAddress('_ZN11BiomeSourceC2EjR5BiomeSt10shared_ptrI5LayerES4_'),
                                                'void',
                                                ['pointer',
                                                 'int32',
                                                 'pointer',
                                                 'pointer',
                                                 'pointer']);

var createDefaultLayers = new NativeFunction(getAddress('_ZN18OverworldDimension19createDefaultLayersExRSt10shared_ptrI5LayerES3_13GeneratorTypeb'),
                                             'void',
                                             ['int64', 'pointer', 'pointer', 'int32', 'uint32']);

var findValidSpawnPosition = new NativeFunction(getAddress('_Z22findValidSpawnPositionR11BiomeSourceiiii'),
                                                'int32',
                                                ['pointer',
                                                 'pointer',
                                                 'int32',
                                                 'int32',
                                                 'int32',
                                                 'int32']);

var fillArea =
    new NativeFunction(getAddress('_ZN15OceanMixerLayer8fillAreaER9LayerDataiiii'),
                       'void', ['pointer', 'pointer', 'int', 'int', 'int', 'int']);

var VillageFeature = new NativeFunction(getAddress('_ZN14VillageFeatureC2Ej'), 'void', ['pointer', 'int']);

var setupChunkSeed = new NativeFunction(getAddress('_ZN12LargeFeature14setupChunkSeedEjR6Randomii'), 'void', ['int', 'pointer', 'int', 'int']);

var isFeatureChunk = new NativeFunction(getAddress('_ZN14VillageFeature14isFeatureChunkEP11BiomeSourceR6RandomRK8ChunkPos'),
                                        'int',
                                        ['pointer', 'pointer', 'pointer', 'pointer']);


function allocLayerData(size) {
    var layerData = Memory.alloc(8 + size);
    var left = layerData.add(8);
    var right = layerData.add(8 + size / 2);
    Memory.writePointer(layerData, left);
    Memory.writePointer(layerData.add(4), right);
    return layerData;
}

function createSourceAndLayers(seed) {
    var layer1 = Memory.alloc(8);
    var layer2 = Memory.alloc(8);
    createDefaultLayers(seed, layer1, layer2, 1, 0);
    var source = Memory.alloc(512);
    biomeSourceConstructor(source, seed, biomePlains, Memory.dup(layer1, 8), Memory.dup(layer2, 8));

    return {
        biomeSource: source,
        layer1full: layer1,
        layer2full: layer2,
        layer1: Memory.readPointer(layer1),
        layer2: Memory.readPointer(layer2)
    };
}

function findSpawn(source) {
    var spawnX = 0;
    var spawnZ = 0;

    var pos = Memory.alloc(1024);

    while (true) {
        var v = findValidSpawnPosition(pos, source, spawnX, spawnZ, 10, 4);

        if (v != 0) {
            break;
        }

        spawnX += 40;
    }

    return [Memory.readS32(pos.add(4)), Memory.readS32(pos.add(12))];
}

function getBiomes(layer, layerData, x, z) {
    fillArea(layer, layerData, x, z, BIOME_TILE_SIZE, BIOME_TILE_SIZE);
    var data = Memory.readPointer(layerData);
    var biomes = Memory.readByteArray(data, BIOME_TILE_SIZE * BIOME_TILE_SIZE * 4);
    return biomes;
}

function findVillages(feature, random, source, pos, seed) {
    VillageFeature(feature, seed);

    for (var i = -250; i < 250; i++) {
        for (var j = -250; j < 250; j++) {
            setupChunkSeed(seed, random, i, j);
            Memory.writeS32(pos, i);
            Memory.writeS32(pos.add(4), j);
            var isVillage = isFeatureChunk(feature, source, random, pos);
            if (isVillage === 1) {
                console.log('Village at ' + i * 16 + ' ' + j * 16);
            }
        }
    }
}

function sendSeedData(layerData, seed) {
    var stuff = createSourceAndLayers(seed);
    var source = stuff.biomeSource;
    var spawn = findSpawn(source);
    var layer = stuff.layer1;

    var radius = 4;

    var x = Math.round(spawn[0] / 4) - radius * BIOME_TILE_SIZE;
    var z = Math.round(spawn[1] / 4) - radius * BIOME_TILE_SIZE;

    var maxI = radius * 2;
    var maxJ = radius * 2;

    send({'type': 'seed', 'seed': seed, 'x': x, 'z': z, 'max_i': maxI, 'max_j': maxJ});

    var feature = Memory.alloc(4096);
    var random = Memory.alloc(4096);
    var pos = Memory.alloc(4096);
    findVillages(feature, random, source, pos, seed);

    for (var i = 0; i < maxI; i++) {
        for (var j = 0; j < maxJ; j++) {
            var biomes = getBiomes(layer, layerData,
                                   x + i * BIOME_TILE_SIZE, z + j * BIOME_TILE_SIZE);
            send({'type': 'data', 'i': i, 'j': j}, biomes);
        }
    }

    send({'type': 'done'})
}

function main() {
    console.log('start');

    var layerData = allocLayerData(1000000);

    var start = 12345678;
    var count = 10000;
    for (var seed = start; seed < start + count; seed++) {
        sendSeedData(layerData, seed);
    }

    console.log('stop');
}

console.log('hook');
setTimeout(main, 500);
