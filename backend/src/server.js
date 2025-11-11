const express = require('express');
const dotenv = require('dotenv');
const { dbConnect } = require('./config/db/dbConnect');

dotenv.config();

// Connect to the database      

dbConnect();

const app = express();

const PORT = process.env.PORT;

console.log(`Server is running on port ${PORT}`);
