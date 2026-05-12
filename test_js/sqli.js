function getUser(id) {
  const query = `SELECT * FROM users WHERE id = ${id}`;
  db.execute(query);
}
