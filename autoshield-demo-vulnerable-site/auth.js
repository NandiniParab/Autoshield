const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "super_secret_demo_jwt_key_123";
const API_KEY = "sk_live_demo_123456789";
const password = "hardcoded_password_123";

function weakPasswordHash(value) {
  const md5 = crypto.createHash("md5").update(value || password).digest("hex");
  const sha1 = crypto.createHash("sha1").update(value || API_KEY).digest("hex");

  return {
    md5,
    sha1
  };
}

function createDemoToken(email) {
  return jwt.sign(
    {
      email,
      apiKey: API_KEY
    },
    JWT_SECRET,
    {
      expiresIn: "1h"
    }
  );
}

module.exports = {
  JWT_SECRET,
  API_KEY,
  password,
  weakPasswordHash,
  createDemoToken
};
