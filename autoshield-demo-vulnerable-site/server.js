const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const child_process = require("child_process");
const path = require("path");
const _ = require("lodash");
const minimist = require("minimist");

const { getUserByEmail } = require("./db");
const auth = require("./auth");

const app = express();
const port = 4000;

app.use(cors({ origin: "*" }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.cookie("session", "demo-session-token");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/user", (req, res) => {
  const email = req.query.email;
  getUserByEmail(email, res);
});

app.get("/ping", (req, res) => {
  const host = req.query.host || "127.0.0.1";
  child_process.exec("ping -n 1 " + host, (error, stdout, stderr) => {
    if (error) {
      res.status(500).send("<pre>" + stderr + "</pre>");
      return;
    }

    res.send("<pre>" + stdout + "</pre>");
  });
});

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.cookie("last_search", q);
  res.send(`<h2>Results for ${q}</h2><p><a href="/">Back to demo</a></p>`);
});

app.post("/login", (req, res) => {
  const email = req.body.email || "demo@example.com";
  const password = req.body.password || "";
  const token = auth.createDemoToken(email);
  const hashedPassword = auth.weakPasswordHash(password);

  res.cookie("session", token);
  res.json({
    ok: true,
    token,
    hashedPassword,
    options: minimist(["--role", "admin"]),
    lodashVersion: _.VERSION
  });
});

app.listen(port, () => {
  console.log(`AutoShield vulnerable demo running at http://localhost:${port}`);
});
