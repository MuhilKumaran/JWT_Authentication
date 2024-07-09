express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const db = require("./mysql");
const cookieParser = require("cookie-parser");
const { createTokens, validateToken } = require("./JWT");

app.use(express.json());
app.use(cookieParser());


//   const { username, password } = req.body;

//   bcrypt.hash(password, 10).then((hash) => {
//     const sql = "insert into users(username,password) values( ? ,? )";
//     db.query(sql, [username, hash], (err, result) => {
//       if (err) {
//         console.log(err);
//         return res.status(400).json("Error occures");
//       }
//       return res.status(200).json("User Registered");
//     });
//   });
// });
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO users (username, password) VALUES (?, ?)";

    db.query(sql, [username, hash], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(400).json("Error occurs");
      }
      return res.status(200).json("User Registered");
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json("Internal Server Error");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  db.query(
    "SELECT username, password FROM users WHERE username = ?",
    [username],
    (error, results) => {
      if (error) {
        console.error("Error fetching user:", error);
        return res.status(500).json("Error fetching user");
      }

      if (results.length === 0) {
        return res.status(404).json("User not found");
      }

      const userdata = results[0];
      console.log(userdata.password);
      bcrypt.compare(password, userdata.password).then((match) => {
        console.log(match);
        if (!match) {
          return res.status(400).json("Invalid Password");
        }
        const acccessToken = createTokens(userdata);
        //expire after 30 days
        res.cookie("access-token", acccessToken, {
          maxAge: 60 * 60 * 23 * 30 * 1000,
          httpOnly: true,
        });
        return res.status(200).json(userdata);
      });
    }
  );
});

app.get("/profile", validateToken, (req, res) => {
  res.json("profile");
});

app.listen(3001, () => {
  console.log("Server islisening to 3001");
});
