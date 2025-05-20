// cron/cronJobs.js
const cron = require('node-cron');
const { cloneOrUpdateMITRERepo, parseCVEData } = require('../services/mitreService');
const connectDB = require('../config/db');
const logger = require('../logger');
const { computeWatchlistStats } = require("../controllers/watchlistController");

async function setupCronJobs() {
  const db = await connectDB();

  // Set up a daily job to pull from MITRE and update the database
  cron.schedule("*/3 * * * *", async () => {
    logger.info("Running daily MITRE update...");
    cloneOrUpdateMITRERepo();
    parseCVEData(db);
  });

   // Compute and update watchlist stats daily at midnight
   cron.schedule("0 0 * * *", async () => {
    logger.info("Running watchlist stats computation...");
    try {
      await computeWatchlistStats(db);
      logger.info("Watchlist stats computation completed.");
    } catch (error) {
      logger.error("Error computing watchlist stats:", error);
    }
  });
}

module.exports = setupCronJobs;
