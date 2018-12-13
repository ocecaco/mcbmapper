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

var biomeSourceConstructor = new NativeFunction(getAddress('_ZN11BiomeSourceC2EjRK13BiomeRegistryR5BiomeSt10shared_ptrI5LayerES7_'),
                                                'void',
                                                ['pointer', // this
                                                 'int32', // seed
                                                 'pointer', // biomeregistry
                                                 'pointer', // biome
                                                 'pointer', // layer1
                                                 'pointer']); // layer2

var createDefaultLayers = new NativeFunction(getAddress('_ZN18OverworldDimension19createDefaultLayersExRK13BiomeRegistryRSt10shared_ptrI5LayerES6_13GeneratorTypeb'),
                                             'void',
                                             ['int64', // seed
                                              'pointer', // biomeregistry
                                              'pointer', // layer1
                                              'pointer', // layer2
                                              'int32', // generatortype
                                              'uint32']); // bool flag

var findValidSpawnPosition = new NativeFunction(getAddress('_Z22findValidSpawnPositionR11BiomeSourceiiii'),
                                                'int32',
                                                ['pointer', // return value
                                                 'pointer', // biomesource
                                                 'int32', // x
                                                 'int32', // z
                                                 'int32', // ? constant
                                                 'int32']); // ? constant

var biomeRegistryCtor = new NativeFunction(getAddress('_ZN13BiomeRegistryC2Ev'),
                                           'void',
                                           ['pointer']); // this

var initBiomes = new NativeFunction(getAddress('_ZN13VanillaBiomes10initBiomesER13BiomeRegistry'),
                                    'void',
                                    ['pointer']); // biomeregistry

var registrationFinished = new NativeFunction(getAddress('_ZN13BiomeRegistry20registrationFinishedEv'),
                                              'void',
                                              ['pointer']); // biomeregistry (this)

var fillArea =
    new NativeFunction(getAddress('_ZN15OceanMixerLayer8fillAreaER9LayerDataiiii'),
                       'void',
                       ['pointer', // layer
                        'pointer', // layerdata
                        'int', // x
                        'int', // z
                        'int', // ? constant
                        'int']); // ? constant

var VillageFeature = new NativeFunction(getAddress('_ZN14VillageFeatureC2Ej'),
                                        'void',
                                        ['pointer', // this
                                         'int']); // seed

var setupChunkSeed = new NativeFunction(getAddress('_ZN12LargeFeature14setupChunkSeedEjR6Randomii'),
                                        'void',
                                        ['int', // seed
                                         'pointer', // random
                                         'int', // x
                                         'int']); // z

var isFeatureChunk = new NativeFunction(getAddress('_ZN14VillageFeature14isFeatureChunkEP11BiomeSourceR6RandomRK8ChunkPos'),
                                        'int',
                                        ['pointer', // feature
                                         'pointer', // biomesource
                                         'pointer', // random
                                         'pointer']); // chunkpos


function allocLayerData(size) {
    var layerData = Memory.alloc(8 + size);
    var left = layerData.add(8);
    var right = layerData.add(8 + size / 2);
    Memory.writePointer(layerData, left);
    Memory.writePointer(layerData.add(4), right);
    return layerData;
}

function createSourceAndLayers(registry, seed) {
    var layer1 = Memory.alloc(8);
    var layer2 = Memory.alloc(8);
    createDefaultLayers(seed, registry, layer1, layer2, 1, 0);
    var source = Memory.alloc(512);
    biomeSourceConstructor(source, seed, registry, biomePlains, Memory.dup(layer1, 8), Memory.dup(layer2, 8));

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

function findVillages(feature, random, source, pos, seed, startChunk, stopChunk) {
    var villages = [];
    VillageFeature(feature, seed);

    for (var i = startChunk[0]; i < stopChunk[0]; i++) {
        for (var j = startChunk[1]; j < stopChunk[1]; j++) {
            setupChunkSeed(seed, random, i, j);
            Memory.writeS32(pos, i);
            Memory.writeS32(pos.add(4), j);
            var isVillage = isFeatureChunk(feature, source, random, pos);
            if (isVillage === 1) {
                villages.push([i * 16, j * 16]);
            }
        }
    }

    return villages;
}

function sendSeedData(registry, layerData, seed) {
    var stuff = createSourceAndLayers(registry, seed);
    var source = stuff.biomeSource;
    var spawn = findSpawn(source);
    var layer = stuff.layer1;

    var radius = 50;

    var x = Math.round(spawn[0] / 4) - radius * BIOME_TILE_SIZE;
    var z = Math.round(spawn[1] / 4) - radius * BIOME_TILE_SIZE;

    var maxI = radius * 2;
    var maxJ = radius * 2;

    var length = 2 * radius * BIOME_TILE_SIZE;
    var feature = Memory.alloc(4096);
    var random = Memory.alloc(4096);
    var pos = Memory.alloc(4096);
    var startChunk = [Math.floor(x * 4 / 16), Math.floor(x * 4 / 16)];
    var stopChunk = [Math.ceil((x + length) * 4 / 16),
                     Math.ceil((z + length) * 4 / 16)];
    var villages = findVillages(feature, random, source, pos, seed, startChunk, stopChunk);

    send({'type': 'seed', 'seed': seed, 'x': x, 'z': z, 'max_i': maxI, 'max_j': maxJ, 'villages': villages});

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
    var registry = Memory.alloc(8192);
    biomeRegistryCtor(registry);
    initBiomes(registry);
    registrationFinished(registry);

    var start = 37286;
    var count = 1;
    for (var seed = start; seed < start + count; seed++) {
        sendSeedData(registry, layerData, seed);
    }

    console.log('stop');
}

console.log('hook');
setTimeout(main, 500);
