const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const UserModel = require('./users.js');



//responsible for managing user password records in a database
class UserPasswords{
    constructor(db) {
        this.db = db;
        this.usersTable = () => db('users_passwords');
    }
    //This method creates a new user password record in the database.
    async createPasswordRecord(obj){
        const authenticated  = await this.validateEncKey(obj.encKey, obj.user_id);
        if (!authenticated) {
            return false;
        }
        obj.login = this.encrypt(obj.login, obj.encKey); //updating value with encrypted version
        obj.password = this.encrypt(obj.password, obj.encKey);
        obj.shared_by_user_id = null;

        return this.actualPassword(obj); 
    }
    //This method creates the actual password record in the database.
    async actualPassword(obj){
        const db = this.db;

        try{
            const row = {
                user_id: obj.user_id,
                shared_by_user_id: obj.shared_by_user_id,
                password_label: obj.password_label,
                url: obj.url,
                login: obj.login,
                password: obj.password,
            };
        const [insertedRowId] = await db('users_passwords').insert(row);
        return insertedRowId;
        } catch(error){
            throw error;
        }
    }
    //Encryption- Involves updating the cipher with the plaintext data and obtaining the encrypted result.
    encrypt(str, key){
        const iv = crypto.randomBytes(16);
        const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
        const cipher = crypto.createCipheriv('aes-256-ctr', encKey, iv);
      
        let encrypted = cipher.update(str, 'utf-8', 'base64');
        encrypted += cipher.final('base64');
      
        const encryptedData = `${encrypted}-${iv.toString('base64')}`; 
        return encryptedData;
      }
      
    decrypt(encStr, key){
        const encArr = encStr.split('-');
        const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
        const decipher = crypto.createDecipheriv('aes-256-ctr', encKey, Buffer.from(encArr[1], 'base64'));
        let decrypted = decipher.update(encArr[0], 'base64', 'utf-8'); 
        decrypted += decipher.final('utf-8');
        return decrypted;
    }

    async validateEncKey(key, userId) {
        const userModel = new UserModel(this.db); 
        const userObj = await userModel.get(userId);
        return await bcrypt.compare(key, userObj.password_encryption_key);
      }
      
    
    async list(obj) {
      try {
          const { encKey, user_id } = obj;
          const results = await this.usersTable()
              .where('user_id', user_id)
              .whereNull('shared_by_user_id')
              .select('login', 'password');

          return results.map(({ login, password }) => ({
              login: this.decrypt(login, encKey),
              password: this.decrypt(password, encKey)
          }));
      } catch (error) {
          throw error;
      }

    }
    
    async listShared(obj) {
      try {
          const { encKey, user_id } = obj;
          const results = await this.usersTable()
              .where('shared_by_user_id', user_id);

          return results.map((row) => {
              row.login = this.decrypt(row.login, encKey);
              row.password = this.decrypt(row.password, encKey);
              return row;
          });
      } catch (error) {
          throw error;
      }
  }

  async delete(obj) {
    const { user_password_id, user_id } = obj;

    return this.usersTable()
        .where('id', user_password_id)
        .where('user_id', user_id)
        .del();
}

    async getPasswordById(passwordId, encKey) {
      const passwordRow = await this.usersTable()
          .where('id', passwordId)
          .first();

      if (!passwordRow) {
          return false;
      }

      passwordRow.login = this.decrypt(passwordRow.login, encKey);
      passwordRow.password = this.decrypt(passwordRow.password, encKey);

      return passwordRow;
  }
}

module.exports = UserPasswords;