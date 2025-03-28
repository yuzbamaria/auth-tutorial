const { Pool } = require("pg");

require("dotenv").config();

const pool = new Pool();

// console.log(process.env.PGDATABASE);

module.exports = pool;