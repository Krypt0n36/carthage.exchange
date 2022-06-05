const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();
// ssl: { rejectUnauthorized: false }

const pool = new Pool({
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    host: process.env.DB_HOST,
    ssl: false
    
})



module.exports = { pool }
