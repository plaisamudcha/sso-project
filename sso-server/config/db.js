const mongoose = require("mongoose");
const { envConfig } = require("../config/config");

async function connectDB() {
  await mongoose.connect(envConfig.MONGODB_URI);
  console.log("MongoDB connect");
}

module.exports = { connectDB };
