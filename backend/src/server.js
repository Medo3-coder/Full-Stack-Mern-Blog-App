const express = require('express');
const dotenv = require('dotenv');
const authRoutes = require('./routes/auth/authRoutes');
const { dbConnect } = require('./config/db/dbConnect');

dotenv.config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to the database      
dbConnect();

// Routes
app.use('/api/auth' , authRoutes);


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
