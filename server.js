const express = require("express");
const app = express();
const cors = require("cors");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const { v4: uuidv4 } = require("uuid");

app.use(express.json());
app.use(cors());
require("dotenv").config();

const path = require("path");

const dbPath = path.join(__dirname, "storehub.db");

let db;
async function initDbAndServer() {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    app.listen(4002, () => {
      console.log("The server is running at port 4002");
    });
  } catch (err) {
    res.status(500).send({ message: "Internal Server Error" });
    console.log(`Database Error ${err}`);
  }
}

initDbAndServer();

app.post("/signup", async (req, res) => {
  const { name, email, password, address, role = "User" } = req.body;

  // check if user already exists
  const existing = await db.get("SELECT * FROM users WHERE email = ?", [email]);
  if (existing)
    return res.status(400).send({ message: "User already exists." });

  const hashedPassword = await bcrypt.hash(password, 10);
  const id = uuidv4();

  try {
    await db.run(
      "INSERT INTO users (id,name, email, password, address, role) VALUES (?,?, ?, ?, ?, ?)",
      [id, name, email, hashedPassword, address, role]
    );

    res.status(201).send({ message: "User registered successfully." });
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
    if (!user) return res.status(404).send({ msg: "User not found." });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(401).send({ msg: "Invalid password." });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.status(200).send({ token, role: user.role, name: user.name });
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

const authenticateToken = (request, response, next) => {
  let jwtToken;

  const authHeader = request.headers["authorization"];

  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }

  if (jwtToken === undefined) {
    return response.status(401).send({ message: "User not loged in" });
  }

  jwt.verify(jwtToken, process.env.JWT_SECRET, async (err, payload) => {
    if (err) {
      return response.status(401).send({ message: "Invalid JWT token" });
    }

    request.userId = payload.id;
    request.role = payload.role;
    next();
  });
};

const authorizeAdmin = (req, res, next) => {
  if (req.role !== "Admin") {
    return res.status(403).send({ message: "Access denied. Admins only." });
  }
  next();
};

// Route: Add New Store
app.post("/stores", authenticateToken, authorizeAdmin, async (req, res) => {
  const { name, email, address, ownerId } = req.body;

  const id = uuidv4();

  try {
    await db.run(
      "INSERT INTO stores (id, name, email, address,owner_id) VALUES (?, ?, ?, ?,?)",
      [id, name, email, address, ownerId]
    );

    res.status(201).json({ message: "Store added successfully." });
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });

    console.log(error);
  }
});

// Dashboard: Get Summary Stats
app.get("/dashboard", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const userCount = await db.get("SELECT COUNT(*) AS count FROM users");
    const storeCount = await db.get("SELECT COUNT(*) AS count FROM stores");
    const ratingCount = await db.get("SELECT COUNT(*) AS count FROM ratings");

    res.status(200).send({
      totalUsers: userCount.count,
      totalStores: storeCount.count,
      totalRatings: ratingCount.count,
    });
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

app.get("/users", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const query = `
  SELECT 
    users.id, 
    users.name, 
    users.email, 
    users.address, 
    users.role, 
    ROUND(AVG(ratings.rating), 2) AS average_rating
  FROM users
  LEFT JOIN stores ON stores.owner_id = users.id
  LEFT JOIN ratings ON ratings.store_id = stores.id
  GROUP BY users.id
`;

    const users = await db.all(query);

    res.status(200).send(users);
  } catch (error) {
    response.status(500).send({ message: "Internal Serval Error" });
  }
});

app.get("/stores", authenticateToken, async (req, res) => {
  const query = `
    SELECT 
      stores.id,
      stores.name, 
      stores.email, 
      stores.address,
      ROUND(AVG(ratings.rating), 2) AS average_rating
    FROM stores
    LEFT JOIN ratings ON ratings.store_id = stores.id
    GROUP BY stores.id
  `;

  try {
    const stores = await db.all(query);
    res.send(stores);
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

app.put("/update-password", authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  // Validate new password
  const passwordRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,16}$/;
  if (!passwordRegex.test(newPassword)) {
    return res.status(400).send({
      message:
        "New password must be 8-16 chars with one uppercase & one special character.",
    });
  }

  try {
    const user = await db.get("SELECT * FROM users WHERE id = ?", [req.userId]);

    if (!user) return res.status(404).send({ message: "User not found" });

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).send({ message: "Old password is incorrect" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    await db.run("UPDATE users SET password = ? WHERE id = ?", [
      hashedNewPassword,
      req.userId,
    ]);

    res.send({ message: "Password updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/rate-store", authenticateToken, async (req, res) => {
  const { storeId, rating } = req.body;

  if (!storeId || typeof rating !== "number" || rating < 1 || rating > 5) {
    return res
      .status(400)
      .send({ message: "Invalid store ID or rating (1-5)" });
  }

  try {
    const existingRating = await db.get(
      "SELECT * FROM ratings WHERE user_id = ? AND store_id = ?",
      [req.userId, storeId]
    );

    if (existingRating) {
      // Update the existing rating
      await db.run(
        "UPDATE ratings SET rating = ? WHERE user_id = ? AND store_id = ?",
        [rating, req.userId, storeId]
      );
    } else {
      // Submit a new rating
      const id = uuidv4();
      await db.run(
        "INSERT INTO ratings (id, user_id, store_id, rating) VALUES (?, ?, ?, ?)",
        [id, req.userId, storeId, rating]
      );
    }

    res.status(200).send({ message: "Rating submitted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/user/stores", authenticateToken, async (req, res) => {
  const query = `
  SELECT 
    stores.id,
    stores.name, 
    stores.email, 
    stores.address,
    ROUND(AVG(ratings.rating), 2) AS average_rating,
    (
      SELECT rating 
      FROM ratings 
      WHERE user_id = ? AND store_id = stores.id
    ) AS user_rating
  FROM stores
  LEFT JOIN ratings ON ratings.store_id = stores.id
  GROUP BY stores.id
`;

  try {
    const stores = await db.all(query, [req.userId]);
    res.send(stores);
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

app.get("/my-stores/reviews", authenticateToken, async (req, res) => {
  const query = `
  SELECT 
  users.id AS user_id,
  users.name AS user_name,
  users.email AS user_email,
  ratings.rating,
  ratings.store_id,
  stores.name AS store_name
FROM ratings
JOIN users ON ratings.user_id = users.id
JOIN stores ON ratings.store_id = stores.id
WHERE ratings.store_id IN (
  SELECT id FROM stores WHERE owner_id = ?
);
`;
  try {
    const response = await db.all(query, [req.userId]);
    res.status(200).send(response);
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

app.get("/my-stores/ratings", authenticateToken, async (req, res) => {
  const ownerId = req.userId;

  try {
    const storeRatings = await db.all(
      `
      SELECT 
        stores.id,
        stores.name,
        stores.email,
        stores.address,
        ROUND(AVG(ratings.rating), 2) AS average_rating
      FROM stores
      LEFT JOIN ratings ON ratings.store_id = stores.id
      WHERE stores.owner_id = ?
      GROUP BY stores.id
      `,
      [ownerId]
    );

    res.status(200).send(storeRatings);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Error retrieving store ratings." });
  }
});
