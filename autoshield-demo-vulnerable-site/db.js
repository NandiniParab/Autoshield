const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, name TEXT, role TEXT)");
  db.run("INSERT INTO users (email, name, role) VALUES ('alice@example.com', 'Alice Demo', 'admin')");
  db.run("INSERT INTO users (email, name, role) VALUES ('bob@example.com', 'Bob Demo', 'user')");
});

function getUserByEmail(email, res) {
  const query = "SELECT * FROM users WHERE email='" + email + "'";

  db.get(query, (err, row) => {
    if (err) {
      res.status(500).send("Database error: " + err.message);
      return;
    }

    res.json({
      query,
      user: row || null
    });
  });
}

module.exports = { getUserByEmail };
