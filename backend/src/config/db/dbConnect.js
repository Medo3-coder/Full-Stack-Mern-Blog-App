const mongoose = require("mongoose");

const dbConnect = async () => {
  try {
    const connection = await mongoose.connect(process.env.MONGO_URI, {
      dbName: "blogAppDB",
    });

    console.log(`MongoDB connected: ${connection.connection.host}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1); // Stop the app if DB fails to connect
  }
};

module.exports = { dbConnect };