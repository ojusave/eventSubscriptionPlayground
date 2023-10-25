const _cache = {};

class Cache {
    constructor(){}

    get(cacheName, cacheKey){
        return _cache[cacheName] !== undefined ? _cache[cacheName][cacheKey] : undefined;
    }
    
    put(cacheName, cacheKey, cacheValue) {
        if(_cache[cacheName] === undefined) {
            _cache[cacheName] = {};
        }
        _cache[cacheName][cacheKey] = cacheValue;
        
    }
}

module.exports = { Cache };
