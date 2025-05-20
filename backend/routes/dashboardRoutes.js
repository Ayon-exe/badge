const express = require("express");
const router = express.Router();
const connectDB = require("../config/db");
const multer = require('multer');
const logger = require("../logger");
const authMiddleware = require("../server/middleware/auth");
const { getUsername } = require("../controllers/userController");
const {
  getRecentCVEsCount,
  getUnpatchedFixableCVEs,
  getFixablePercentageOfCVEsWithPatchesAvailable,
  getFixableCVEsStats,
  getLiveExploitsForWatchlist,
  getVendorsAndProductsFromWatchlist,
  getVendorDataFromWatchlist,
  getTotalVendors,
  getTotalProducts,
  getTotalOpenCVEs,
  getTotalResolvedCVEs,
  getTotalIgnoredCVEs,
  
  getVendorsAndProductsTotalCVECount
} = require("../controllers/dashboardController");

router.get("/recent-cves/:timeframe", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const { timeframe } = req.params;

    // Validate timeframe
    const validTimeframes = ["daily", "weekly", "monthly"];
    if (!validTimeframes.includes(timeframe)) {
      return res.status(400).json({
        message: "Invalid timeframe. Use 'daily', 'weekly', or 'monthly'.",
      });
    }

    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    const result = await getRecentCVEsCount(db, username, timeframe);
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to fetch unpatched fixable CVEs
router.get("/unpatched-fixable-cves", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    const result = await getUnpatchedFixableCVEs(db, username);
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to fetch fixable percentage of CVEs with patches available
router.get("/fixable-percentage", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    const result = await getFixablePercentageOfCVEsWithPatchesAvailable(
      db,
      username
    );
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to fetch fixable CVE statistics (including classification)
router.get("/fixable-cve-stats", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    const result = await getFixableCVEsStats(db, username);
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to fetch all vendors in a user's watchlist
router.get("/watchlist/vendors", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    const vendors = await getVendorsAndProductsFromWatchlist(db, username);
    res.json({ username, vendors });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to fetch live exploits based on user's watchlist
router.get("/live-exploits", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    const result = await getLiveExploitsForWatchlist(db, username);
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/watchlist-vendor-stats",authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);
    const result = await getVendorDataFromWatchlist(db, username);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/watchlist-vendor-stats-radial",authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);
    const result = await getVendorsAndProductsTotalCVECount(db, username);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/total-vendors", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    const totalVendors = await getTotalVendors(db, username);
    res.json({ totalVendors });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/total-products", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);
    
    const totalProducts = await getTotalProducts(db, username);
    res.json({ totalProducts });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// API route for getting total open CVEs
router.get("/total-open-cves", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);
    
    const totalOpenCVEs = await getTotalOpenCVEs(db, username);
    res.json({ totalOpenCVEs });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// API route for getting total resolved CVEs
router.get("/total-resolved-cves", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);
    
    const totalResolvedCVEs = await getTotalResolvedCVEs(db, username);
    res.json({ totalResolvedCVEs });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// API route for getting total ignored CVEs
router.get("/total-ignored-cves", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);
    
    const totalIgnoredCVEs = await getTotalIgnoredCVEs(db, username);
    res.json({ totalIgnoredCVEs });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});





module.exports = router;
