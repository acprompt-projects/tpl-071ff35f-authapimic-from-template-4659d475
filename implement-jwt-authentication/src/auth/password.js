const bcrypt = require("bcrypt");

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || "12", 10);

async function hashPassword(plaintext) {
  if (!plaintext || typeof plaintext !== "string") {
    throw new Error("hashPassword requires a non-empty string");
  }
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return bcrypt.hash(plaintext, salt);
}

async function verifyPassword(plaintext, hashed) {
  if (!plaintext || !hashed) {
    throw new Error("verifyPassword requires both plaintext and hashed values");
  }
  return bcrypt.compare(plaintext, hashed);
}

async function needsRehash(hashed) {
  const saltRounds = await bcrypt.getRounds(hashed).catch(() => 0);
  return saltRounds < SALT_ROUNDS;
}

module.exports = { hashPassword, verifyPassword, needsRehash };