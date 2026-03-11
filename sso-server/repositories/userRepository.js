const User = require("../model/user");

async function findByEmail(email) {
  return User.findOne({ email });
}

async function findByIdLean(id) {
  return User.findById(id).lean();
}

async function createUser(payload) {
  return User.create(payload);
}

module.exports = {
  findByEmail,
  findByIdLean,
  createUser,
};
