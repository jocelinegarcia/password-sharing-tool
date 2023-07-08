const express = require('express');
const knex = require('knex');
const UserModel = require('../models/users');

const app = express();

const db = knex({
    client: 'sqlite3',
    connection: {
        filename: './dev.sqlite3',
    },
    migrations: {
        tableName: 'migrations'
    },
    useNullAsDefault: true, 
});
const userModel = new UserModel(db);
app.use(express.json()); // Parse JSON bodies

// Signup 
app.post('/signup', async (req, res) => {
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
  
      res.send(`User created successfully`);
    } catch (error) {
      console.error('Signup error:', error);
      res.status(500).send('Error creating user');
    }
  });
  
  
  
// Login 
app.post('/login', async (req, res) => {
    try {
      // Extract the necessary data from the request body
      const { email, password } = req.body;
  
      // Log in the user using the UserModel
      const token = await userModel.logIn(email, password);
  
      res.send(`Logged in. Token: ${token}`);
    } catch (error) {
      console.error('Login error:', error);
      res.status(401).send('Invalid email or password');
    }
  });

   
const port = 8000;
app.listen(port,()=> {
console.log('listen port 8000');
});

app.get('/', (req,res)=>{
    res.send('Hello World');
    });