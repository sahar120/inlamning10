// Importera nödvändiga bibliotek
const express = require("express");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

// Skapa en anslutning till databasen
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "webbserverprogrammering",
});

// Koppla upp mot databasen
connection.connect((err) => {
  if (err) {
    console.error("Fel vid anslutning till databasen: ", err);
    return;
  }
  console.log("Anslutning till databasen lyckades!");
});

// Skapa en instans av express-appen
const app = express();

// Ange vilken port appen ska lyssna på
const port = 3000;

// Ange en ruta för att hämta alla användare
app.get("/users", authenticateToken, (req, res) => {
  // Skicka en SQL-fråga till databasen för att hämta alla användare
  connection.query("SELECT * FROM users", (error, results) => {
    if (error) {
      console.error("Fel vid hämtning av användare: ", error);
      res.status(500).send("Ett fel uppstod vid hämtning av användare");
      return;
    }

    // Skicka tillbaka användardata som JSON
    res.send(results);
  });
});

// Ange en ruta för att hämta en specifik användare baserat på ID
app.get("/users/:id", authenticateToken, (req, res) => {
  const userId = req.params.id;

  // Skicka en SQL-fråga till databasen för att hämta en specifik användare baserat på ID
  connection.query(
    "SELECT * FROM users WHERE id = ?",
    [userId],
    (error, results) => {
      if (error) {
        console.error("Fel vid hämtning av användare: ", error);
        res.status(500).send("Ett fel uppstod vid hämtning av användare");
        return;
      }

      // Skicka tillbaka användardata som JSON
      res.send(results);
    }
  );
});

// Funktion för att autentisera JWT-token
function authenticateToken(req, res, next) {
  // Hämta autentiseringsheadern från requesten
  const authHeader = req.headers["authorization"];
  // Hämta token från headern (format: "Bearer TOKEN")
  const token = authHeader && authHeader.split(" ")[1];

  // Om inget token hittades, skicka felmeddelande och status 401 (unauthorized)
  if (token == null) {
    return res
      .status(401)
      .send("Du måste vara inloggad för att kunna använda denna funktionen");
  }

  // Verifiera JWT-token
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    // Om tokenet är ogiltigt, skicka felmeddelande och status 403 (forbidden)
    if (err) {
      return res.status(403).send("Ogiltigt inloggningsförsök");
    }

    // Spara användarinformationen i request-objektet
    req.user = user;
    next();
  });
}

const saltRounds = 10;

app.post("/addusers", (req, res) => {
  const { username, firstname, lastname, password } = req.body;

  // Kryptera lösenordet med bcrypt
  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      console.error("Fel vid kryptering av lösenord: ", err);
      res.status(500).send("Ett fel uppstod vid kryptering av lösenord");
      return;
    }

    // Lägg till användaren med krypterat lösenord i databasen
    const sql = `INSERT INTO users (username, firstname, lastname, password) VALUES (?, ?, ?, ?)`;
    db.query(
      sql,
      [username, firstname, lastname, hashedPassword],
      (err, result) => {
        if (err) {
          console.error("Fel vid tilläggning av användare: ", err);
          res.status(500).send("Ett fel uppstod vid tilläggning av användare");
          return;
        }

        console.log(`User ${username} added successfully.`);
        res.send(`User ${username} added successfully.`);
      }
    );
  });
});

// Ange en ruta för att uppdatera en specifik användare baserat på ID
app.put("/users/:id", (req, res) => {
  const userId = req.params.id;
  const { username, firstname, lastname, password } = req.body;

  // Kryptera lösenordet med bcrypt
  bcrypt.hash(password, saltRounds, (error, hashedPassword) => {
    if (error) {
      console.error("Fel vid kryptering av lösenord: ", error);
      res.status(500).send("Ett fel uppstod vid uppdatering av användare");
      return;
    }

    // Skicka en SQL-fråga till databasen för att uppdatera en specifik användare baserat på ID
    connection.query(
      "UPDATE users SET username = ?, firstname = ?, lastname = ?, password = ? WHERE id = ?",
      [username, firstname, lastname, hashedPassword, userId],
      (error, results) => {
        if (error) {
          console.error("Fel vid uppdatering av användare: ", error);
          res.status(500).send("Ett fel uppstod vid uppdatering av användare");
          return;
        }

        // Skicka tillbaka ett meddelande om att användaren har uppdaterats
        res.send(`Användaren med ID ${userId} har uppdaterats`);
      }
    );
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username = ?`;
  db.query(sql, [username], (err, result) => {
    if (err) throw err;
    if (result.length === 0) {
      res.status(401).send("Invalid username or password.");
    } else {
      const user = result[0];
      bcrypt.compare(password, user.password, (err, match) => {
        if (err) throw err;
        if (!match) {
          res.status(401).send("Invalid username or password.");
        } else {
          const token = jwt.sign({ id: user.id }, "secret", {
            expiresIn: "1h",
          });
          res.json({ token });
        }
      });
    }
  });
});

// Starta appen och lyssna på angiven port
app.listen(port, () => {
  console.log(`Programmet lyssnar på port ${port}`);
});
