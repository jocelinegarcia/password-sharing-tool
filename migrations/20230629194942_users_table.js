/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.createTableIfNotExists('users', table => {
    table.increments('id');
    table.string('name', 255).notNullable();
    table.string('email', 255).notNullable().unique; //everyone has unique emails
    table.string('password', 255).notNullable();
    table.string('password_encryption_key', 255).notNullable();
    table.datetime('deleted_at').nullable();
    table.timestamps(true, true);
  })
  .createTableIfNotExists('users_passwords', table =>{
    table.increments('id');
    table.integer('user_id', 11).notNullable();
    table.integer('shared_by_user_id', 11).nullable();
    table.string('password_label', 255).notNullable();
    table.string('url', 255).notNullable();
    table.string('login', 255).notNullable();
    table.string('password', 255).notNullable();
    table.datetime('deleted_at').nullable()
    table.timestamps(true, true);
    });

};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.dropTable('users')
  .dropTable("users_passwords");

};
