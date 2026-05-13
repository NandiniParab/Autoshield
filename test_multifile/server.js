const express = require("express");
const { getUserByEmail } = require("./db");

const app = express();

app.get("/user", (req, res) => {
  const email = req.query.email;
  getUserByEmail(email, res);
});
