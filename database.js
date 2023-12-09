const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();
// ssl: { rejectUnauthorized: false }

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
})



module.exports = { pool }
