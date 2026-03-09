const mongoose = require("mongoose");
const crypto = require("crypto");
const { envConfig } = require("../config/config");
const User = require("../model/user");

function ensureMongoDbName(uri) {
  // Keep current URI as-is; this helper only warns when DB name is omitted.
  const hasDbName = /mongodb(\+srv)?:\/\/[^/]+\/[^?]+/i.test(uri || "");
  if (!hasDbName) {
    console.warn(
      "Warning: MONGODB_URI has no explicit DB name. Consider using ...mongodb.net/<dbName>?... to avoid writing to default test DB.",
    );
  }
}

async function run() {
  ensureMongoDbName(envConfig.MONGODB_URI);

  await mongoose.connect(envConfig.MONGODB_URI);
  console.log("Connected to MongoDB");

  const users = await User.find({}, { _id: 1, email: 1, sub: 1, emailVerified: 1 }).lean();

  let updated = 0;
  for (const user of users) {
    const patch = {};

    if (!user.sub) {
      patch.sub = crypto.randomUUID();
    }

    if (typeof user.emailVerified !== "boolean") {
      patch.emailVerified = false;
    }

    if (Object.keys(patch).length > 0) {
      await User.updateOne({ _id: user._id }, { $set: patch });
      updated += 1;
    }
  }

  console.log(`Backfill completed. Updated ${updated} / ${users.length} users.`);
  await mongoose.disconnect();
}

run().catch(async (err) => {
  console.error("Backfill failed:", err);
  try {
    await mongoose.disconnect();
  } catch { }
  process.exit(1);
});
