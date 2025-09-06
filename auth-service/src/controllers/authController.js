const pool = require("../db");
const bcrypt = require("bcrypt");

// Signup (manual)
exports.signup = async (req, res) => {
 
  const { name , email, password } = req.body;

  if (!name || !email || !password) 
    return res.status(400).json({ error: "name, email and password required" });

  try {

    const hash = await bcrypt.hash(password, 10);

    const r = await pool.query(
      "INSERT INTO users (name, email, password_hash, google_id) VALUES ($1, $2, $3, NULL) RETURNING id, email",
      [name, email, hash]
    );

    res.json(r.rows[0]);

  } catch (err) {
    res.status(400).json({ error: err });
  }
};

// Login (manual)
exports.login = async (req, res) => {
  
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email and password required" });

  try {
    const r = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    
    if (!r.rows.length) 
      return res.status(400).json({ error: "Invalid credentials" });

    const user = r.rows[0];
    if (!user.password_hash) 
      return res.status(400).json({ error: "Account exists via Google. Use gateway flow to set password." });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) 
      return res.status(400).json({ error: "Invalid credentials" });

    res.json({ id: user.id, email: user.email });
    
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
};
