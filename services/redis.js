const { redis } = require('../config/config');


const client = redis.createClient({
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: process.env.REDIS_PORT || 6379
});

client.on('connect', () => {
    console.log('Connected to Redis');
});
client.on('error', (err) => {
    console.log('Redis error: ' + err);
});

function clearRedisCache() {
    client.flushdb((err, succeeded) => {
        if (err) {
            console.error('Failed to clear Redis cache:', err);
        } else {
            console.log('Successfully cleared Redis cache:', succeeded); // will be true if success
        }
    });
}

module.exports = {
    client,
    clearRedisCache
};


