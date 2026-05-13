function getUserByEmail(email, res) {
  const query = "SELECT * FROM users WHERE email='" + email + "'";
  db.query(query, (err, result) => {
    res.send(result);
  });
}

module.exports = { getUserByEmail };
