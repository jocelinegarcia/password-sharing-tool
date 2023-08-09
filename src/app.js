require("dotenv").config();
const express = require("express");
const app = express();
const { expressjwt} =  require("express-jwt");
const knex = require("knex");
const UserModel = require("../models/users");
const UserPasswords = require("../models/user_passwords");
const knexConfig = require("../knexfile");
const env = process.env.NODE_ENV || "development";
const db = knex(knexConfig[env]); 

const userModel = new UserModel(db);


app.use(express.json());
app.use(
  expressjwt({
    secret: process.env.JWT_SECRET,
    algorithms: ["HS256"],
  }).unless({ path: ["/login", "/signup", "/"] })
);

const port = 8000;
app.listen(port,()=> {
console.log('listen port 8000');
});

app.get('/', (req,res)=>{
  res.status(200).json({message: "Hello"});
    });


// Signup
app.post("/signup", async (req, res) => {
  try {
    // Extract the necessary data from the request body
    const { name, email, password, encryptionKey } = req.body;

    // Create a new user using the UserModel
    const userId = await userModel.createUser({
      name,
      email,
      password,
      encryptionKey,
    });

    res.status(200).json({ message: `User created with ID: ${userId}` });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ error: "Error creating user" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    // Extract the necessary data from the request body
    const { email, password } = req.body;

    // Log in the user using the UserModel
    const token = await userModel.logIn(email, password);

    res.status(200).json({ token: token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(401).json({ error: "Invalid email or password" });
  }
});

// Save Password endpoint to store user passwords
app.post("/save-password", async (req, res) => {
  try {
    req.body.user_id = req.auth.id; 
    const userPasswords = new UserPasswords(db);
    const obj = await userPasswords.createPasswordRecord(req.body);


    if (!obj) {
      return res.status(403).json({ message: 'Invalid key, authentication fail' }); // Respond with an error message if authentication fails
    }

    res.json({ message: 'done', status: 200 }); 
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Internal Service Error' }); 
  }
});

// List Password endpoint to retrieve user passwords
app.post("/list-passwords", async (req, res) => {
  try {
    req.body.user_id = req.auth.id; 
    const result = await new UserPasswords(db).list(req.body);

    if (!result) {
      return res.status(403).json({ message: 'Invalid' }); 
    }

    res.json({ message: 'success', data: result, status: 200 }); 
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Internal Service Error' }); 
  }
});

// Share Password endpoint to share passwords with other users
app.post('/share-password', async (req, res) => {
  try {
    const passwordId = req.body.passwordId;
    const encKey = req.body.encKey;
    const email = req.body.inviteEmail;

    const inviteUser = await new UserModel(db).getByEmail(email);

    if (!inviteUser) {
      return res.status(400).json({ message: 'Unable to share: User does not exist' });
    }

    const passwordRow = await new UserPasswords(db).getPasswordById(passwordId, encKey);

    if (!passwordRow) {
      return res.status(403).json({ message: 'Invalid Password Id' });
    }

    const userPasswords = new UserPasswords(db);

    await userPasswords.actualPassword({
      user_id: inviteUser.id,
      shared_by_user_id: req.auth.id,
      password_label: passwordRow.password_label,
      url: passwordRow.url,
      encKey: process.env.SYS_ENC_KEY,
      login: userPasswords.encrypt(passwordRow.login, process.env['SYS_ENC_KEY']),
      password: userPasswords.encrypt(passwordRow.password, process.env['SYS_ENC_KEY'])
    });

    res.json({ message: 'done', status: 200 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'internal_server_error' });
  }
}); 

// List Shared Passwords endpoint to retrieve shared passwords
app.post("/list-shared-passwords", async (req, res) => {
  try {
    req.body.user_id = req.auth.id; 
    const obj = await new UserPasswords(db).listShared(req.body);

    if (!obj) {
      return res.status(403).json({ message: 'Invalid' }); 
    }

    res.json({ message: 'Success', data: obj, status: 200 }); 
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Internal Service Error' }); 
  }
});

app.delete('/user-password/:id', async (req, res) => {
  try {
      req.body.user_id = req.auth.id;
      const numDeleted = await new UserPasswords(db).delete({
          user_id: req.auth.id,
          user_password_id: req.params.id
      });
      if (!numDeleted && numDeleted !== 0) {
          return res.status(403).json({message: 'Invalid key'});
      }
      res.json({message: 'success', data: `Deleted ${numDeleted} record(s)`, status: 200});
  } catch (e) {
      console.error(e);
      res.status(500).json({message: 'internal_server_error'})
  }
});

