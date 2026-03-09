const { createClient } = require('redis');
const envConfig = require('./config');

const redisClient = createClient({
  url: envConfig.REDIS_URL,
})

redisClient.connect().catch(console.error);

module.exports = redisClient;