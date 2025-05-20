const logger = require('../logger');
const { MongoClient } = require("mongodb");
require("dotenv").config(); // Load .env variables

const mongoURI =
  process.env.MONGO_URI || "mongodb://localhost:27017/cve-database"; // Use default if not in env

if (!mongoURI) {
  logger.error("MongoDB connection string is missing!");
  process.exit(1);
}

let dbInstance = null;
let client = null;

async function connectDB() {
  if (dbInstance) {
    logger.debug("DB instance already exists. Returning existing instance.");
    return dbInstance;
  }
  try {
    client = new MongoClient(mongoURI, {
      maxPoolSize: 10,
      minPoolSize: 1,
      serverSelectionTimeoutMS: 5000,
    });
    await client.connect();
    logger.info("Connected to MongoDB");

    dbInstance = client.db();
    return dbInstance;
  } catch (error) {
    logger.error("Error connecting to MongoDB:", error);
    process.exit(1);
  }
}

process.on("SIGINT", async () => {
  try {
    if (client) {
      await client.close();
      logger.info("MongoDB connection closed successfully.");
    }
  } catch (error) {
    logger.error("Error closing MongoDB connection:");
    logger.error( error);
  } finally {
    process.exit(0);
  }
});
module.exports = connectDB;
// const logger = require("../logger");
// const { MongoClient } = require("mongodb");
// require("dotenv").config(); // Load .env variables
// 
// const mongoURI =
//   process.env.MONGO_URI || "mongodb://localhost:27017/cve-database"; // Use default if not in env
// 
// if (!mongoURI) {
//   logger.error("MongoDB connection string is missing!");
//   process.exit(1);
// }
// 
// const client = new MongoClient(mongoURI); // No need for useNewUrlParser and useUnifiedTopology
// 
// async function connectDB() {
//   try {
//     await client.connect();
//     logger.info("Connected to MongoDB");
//     return client.db(); // Return the database object for further use
//   } catch (err) {
//     logger.error("Error connecting to MongoDB:", err);
//     process.exit(1);
//   }
// }
// 
// module.exports = connectDB;
