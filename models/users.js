const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

//represents user model 
class UserModel {
  constructor(db) {
    this.db = db;
    this.usersTable = () => db('users'); //ref to user table in database
  }

  async hashStr(str) {
    // Hash the given string using bcrypt
    const salt = await bcrypt.genSalt(10);  // Generate a salt with cost factor 10
    const hash = await bcrypt.hash(str, salt); // Hash the string using the generated salt
    return hash;
  }
  async getJwt(obj) {
    try{
     return new Promise((resolve, reject) => { 
        // Generate a JWT token with the provided object and the JWT_SECRET from environment variables
        jwt.sign({ id: obj.id }, process.env.JWT_SECRET, { algorithm: 'HS256' }, function(err, token){
            if(err){ reject (err); 
            } else{
                resolve(token); 
            }
        }); 
     });
    } catch(error){
        throw new InternalError(); // Throw an InternalError if an error occurs during token generation
    }
  }

  async createUser(obj) {
    try {
      const { name, email, password, encryptionKey } = obj;
      const hashedPassword = await this.hashStr(password); //hash users password
      const hashedEncryptionKey = await this.hashStr(encryptionKey); //hash encryption key
      const [result] = await this.usersTable().insert(
        {
          name,
          email,
          password: hashedPassword,
          password_encryption_key: hashedEncryptionKey,
        },
      );
      return result;
      
    } catch (error) {
      throw error; // propogate error further, so route handler can catch it
    }
  }

  async logIn(email, password) {
    try {
      // Check if the user with the provided email exists
      const user = await this.usersTable().where({ email }).first();
      if (!user) {
        throw new Error(`No user associated with the email ${email}`);
      }
      // Compare the provided password with the hashed password from the database
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        throw new Error("Invalid password");
      }

      //generates jwt token
      const token = await this.getJwt({ id: user.id });
      return token;
    } catch (error) {
      throw error;
    }
  }
  async get(id) {
    console.log(id);
    try {
      const user = await this.usersTable().where({id: id}).first();
      return user;
    } catch (error) {
      throw error;
    }
  }
  
  async getByEmail(email) {
    try {
      const user = await this.usersTable().where({email}).first();
      return user;
    } catch (error) {
      throw error;
    }
  }
   
}

module.exports = UserModel;