const logger = require("../logger");
const express = require("express");
const router = express.Router();
const authMiddleware = require("../server/middleware/auth");
const { getUsername } = require("../controllers/userController");
const { body, validationResult } = require("express-validator");

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

const connectDB = require("../config/db");
const {
  getFixableCves,
  renameWatchlist,
  addVendorToWatchlist,
  addProductToWatchlist,
  getWatchlist,
  removeVendorFromWatchlist,
  removeProductFromWatchlist,
  getCvesByVendorsAndProducts,
  removeWatchlist,
  createWatchlist,
  getWatchlistCVEStats,
  computeWatchlistStats,
  getWatchlistProductsAndVendors,
  getAllCvesByVendorsAndProducts,
  getAllProductCvesCombined,
  updateCveStatuses,
  getUserCveStatuses,
  syncWatchlistWithResolutions,
  getCvesByVendorsInMultipleWatchlists,
  getCVEsForProductVersion,
  performResolutionBeforeUpdate,
} = require("../controllers/watchlistController");

const NodeCache = require("node-cache");
const cache = new NodeCache({ stdTTL: 3600 }); // Cache TTL of 1 hour
const MAX_WATCHLIST_SIZE = 5;

// POST route to add an item (vendor/product) to the watchlist
router.post(
  "/watchlist/item",
  authMiddleware,
  body("watchlist").notEmpty().isString(),
  body("vendor").optional().isString(),
  body("product").optional().isString(),
  validateRequest,
  async (req, res) => {
    logger.info(`POST: /watchlist/item`);
    try {
      const db = await connectDB();
      const { vendor, product, watchlist, version } = req.body;
      const authHeader = req.headers.authorization;
      const username = await getUsername(db, authHeader);

      if (!watchlist) {
        return res
          .status(400)
          .json({ success: false, message: "Watchlist name is required" });
      }

      let result;
      if (vendor) {
        result = await addVendorToWatchlist(db, username, watchlist, vendor);
      } else if (product) {
        result = await addProductToWatchlist(
          db,
          username,
          watchlist,
          product,
          version
        );
      }

      // Get updated watchlist data
      const updatedWatchlist = await getWatchlist(db, username);

      return res.status(200).json({
        success: true,
        message: result.message,
        watchlist: updatedWatchlist,
      });
    } catch (err) {
      logger.error(err);
      return res.status(500).json({
        success: false,
        message: "Failed to add item to watchlist",
        error: err.message,
      });
    }
  }
);

// put route to rename watchlist
router.put(
  "/watchlist",
  authMiddleware,
  body("watchlist").notEmpty().isString(),
  body("newWatchlist").notEmpty().isString(),
  validateRequest,
  async (req, res) => {
    logger.info(`PUT: /watchlist`);
    try {
      const db = await connectDB();
      const { watchlist, newWatchlist } = req.body;
      console.log("inside router", watchlist, newWatchlist);
      const authHeader = req.headers.authorization;
      const username = await getUsername(db, authHeader);

      const existingUser = await getWatchlist(db, username);
      if (
        existingUser &&
        existingUser.watchlists.length >= MAX_WATCHLIST_SIZE
      ) {
        return res
          .status(400)
          .json({
            message: `Cannot add more than ${MAX_WATCHLIST_SIZE} watchlists.`,
          });
      }

      // Create the new watchlist
      const result = await renameWatchlist(
        db,
        username,
        watchlist,
        newWatchlist
      );
      return res.status(200).json(result);
    } catch (err) {
      logger.error(err);
      return res
        .status(500)
        .json({ message: "Server error", error: err.message });
    }
  }
);

// POST route to create a new watchlist
router.post(
  "/watchlist",
  authMiddleware,
  body("watchlist").notEmpty().isString(),
  validateRequest,
  async (req, res) => {
    logger.info(`POST: /watchlist`);
    try {
      const db = await connectDB();
      const { watchlist } = req.body;
      console.log("inside router", watchlist);
      const authHeader = req.headers.authorization;
      const username = await getUsername(db, authHeader);

      const existingUser = await getWatchlist(db, username);
      if (
        existingUser &&
        existingUser.watchlists.length >= MAX_WATCHLIST_SIZE
      ) {
        return res.status(400).json({
          message: `Cannot add more than ${MAX_WATCHLIST_SIZE} watchlists.`,
        });
      }

      // Create the new watchlist
      const result = await createWatchlist(db, username, watchlist);
      return res.status(200).json(result);
    } catch (err) {
      logger.error(err);
      return res
        .status(500)
        .json({ message: "Server error", error: err.message });
    }
  }
);

// Route to get the user's watchlist
router.get("/watchlist", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    logger.info(`GET: /watchlist`);
    const watchlist = await getWatchlist(db, username);
    res.json({ username, watchlists: watchlist?.watchlists || [] });
  } catch (err) {
    logger.error(err);
    return res
      .status(500)
      .json({ message: "Server error", error: err.message });
  }
});

// Route to get the user's CVE feed
router.get("/feed", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const month = parseInt(req.query.month) || null;
    const year = parseInt(req.query.year) || null;
    const selectedWatchlist = req.query.watchlist;
    const status = req.query.status || "open";
    const sortByCVSS = req.query.sort || "lowest-scores-first";

    // Parse filters safely with error handling
    let selectedFilters = [];
    if (req.query.filters) {
      try {
        console.log("Received filters on server:", selectedFilters);
        selectedFilters = JSON.parse(req.query.filters);
      } catch (e) {
        console.error("Error parsing filters:", e);
      }
    }

    // Get filtered CVEs using the controller function
    const { cves, totalPages } = await getAllCvesByVendorsAndProducts(
      db,
      username,
      selectedWatchlist,
      selectedFilters,
      status,
      page,
      limit,
      sortByCVSS,
      year,
      month
    );

    console.log("For username", username);
    console.log(req.query.page);
    console.log(req.query.watchlist);
    console.log(req.query.status);
    console.log(req.query.limit);

    if (req.query.filters) {
      try {
        selectedFilters = JSON.parse(req.query.filters);
        console.log("Received filters on server:", selectedFilters);
      } catch (e) {
        console.error("Error parsing filters:", e);
      }
    }

    return res.status(200).json({
      success: true,
      data: cves,
      pagination: {
        page,
        limit,
        pages: totalPages,
      },
    });
  } catch (err) {
    console.error("Error in feed route:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message,
    });
  }
});

// Route to remove an item from the watchlist
router.delete(
  "/watchlist/item",
  authMiddleware,
  body("watchlist").notEmpty().isString(),
  validateRequest,
  async (req, res) => {
    logger.info("DELETE: /watchlist/item");
    const { vendor, product, watchlist } = req.body;
    if (!watchlist)
      return res.status(400).json({ message: "Watchlist name is required." });

    try {
      const db = await connectDB();
      const authHeader = req.headers.authorization;
      const username = await getUsername(db, authHeader);

      if (vendor) {
        await removeVendorFromWatchlist(db, username, watchlist, vendor);
        return res
          .status(200)
          .json({ message: "Vendor removed from watchlist." });
      } else {
        await removeProductFromWatchlist(db, username, watchlist, product);
        return res
          .status(200)
          .json({ message: "Product removed from watchlist." });
      }
    } catch (err) {
      logger.error(err);
      return res
        .status(500)
        .json({ message: "Server error", error: err.message });
    }
  }
);

// DELETE route to remove a watchlist
router.delete(
  "/watchlist",
  authMiddleware,
  body("watchlist").notEmpty().isString(),
  validateRequest,
  async (req, res) => {
    logger.info(`DELETE: /watchlist`);
    try {
      const db = await connectDB();
      const { watchlist } = req.body;
      if (!watchlist)
        return res.status(400).json({ message: "Watchlist name is required." });

      const authHeader = req.headers.authorization;
      const username = await getUsername(db, authHeader);

      const result = await removeWatchlist(db, username, watchlist);
      return res.status(200).json(result);
    } catch (err) {
      logger.error(err);
      return res
        .status(500)
        .json({ message: "Server error", error: err.message });
    }
  }
);

// Route to manually trigger precomputation of watchlist stats
router.post("/compute-watchlist-stats", async (req, res) => {
  try {
    const db = await connectDB();
    const result = await computeWatchlistStats(db);
    res.status(200).json({
      message: "Watchlist Stats Computed and Stored!",
      details: result,
    });
  } catch (err) {
    logger.error("Error computing watchlist stats:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to fetch precomputed watchlist CVE stats
router.get("/watchlist-stats", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    const result = await getWatchlistCVEStats(db, username);
    if (!result || result.length === 0)
      return res.status(404).json({ message: "No watchlist stats found." });

    res.status(200).json(result);
  } catch (err) {
    logger.error("Error fetching watchlist stats:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Fix the resolutions route

router.get("/resolutions", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;

    // Fix the parameter order here:
    const username = await getUsername(db, authHeader);

    if (!username) {
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized user" });
    }

    // Rest of the function remains the same...
    await syncWatchlistWithResolutions(db, username);

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    const { cves, totalPages } = await getAllProductCvesCombined(
      db,
      username,
      page,
      limit
    );

    return res.status(200).json({
      success: true,
      data: cves,
      pagination: {
        page,
        limit,
        pages: totalPages,
      },
    });
  } catch (err) {
    logger.error("Error in /resolutions route:", err);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

// Add these routes before the module.exports line

// Route to update CVE statuses
router.post(
  "/resolution/status",
  authMiddleware,
  body("cve_ids").isArray().withMessage("cve_ids must be an array"),
  body("status").isIn(["open", "resolved", "manhandled", "ignored"]),
  validateRequest,
  async (req, res) => {
    try {
      const db = await connectDB();
      const authHeader = req.headers.authorization;
      const username = await getUsername(db, authHeader);

      if (!username) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized user",
        });
      }

      const { cve_ids, status } = req.body;

      if (!cve_ids || !Array.isArray(cve_ids) || cve_ids.length === 0) {
        return res.status(400).json({
          success: false,
          message: "Missing or invalid cve_ids",
        });
      }

      if (
        !status ||
        !["open", "resolved", "manhandled", "ignored"].includes(status)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid status value",
        });
      }

      const result = await updateCveStatuses(db, username, cve_ids, status);
      return res.status(200).json(result);
    } catch (err) {
      logger.error("Error in resolution status route:", err);
      return res.status(500).json({
        success: false,
        message: "Server error",
        error: err.message,
      });
    }
  }
);

// Route to get user's CVE statuses
router.get("/resolution/status", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    if (!username) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized user",
      });
    }

    const statuses = await getUserCveStatuses(db, username);
    return res.status(200).json({
      success: true,
      data: statuses,
    });
  } catch (err) {
    logger.error("Error in get resolution status route:", err);
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: err.message,
    });
  }
});

// router.get("/watchlist/products", authMiddleware, getUserWatchlistProducts);

router.get("/watchlist/products", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    // Fetch user's watchlist from MongoDB
    const userWatchlist = await db
      .collection("watchlist")
      .findOne({ username });

    // If no watchlist is found for the user
    if (!userWatchlist || !userWatchlist.watchlists.length) {
      return res.status(404).json({
        username,
        message: "No products in the watchlist.",
      });
    }

    // Extract product names from all watchlists
    const productNames = userWatchlist.watchlists
      .flatMap((watchlist) => watchlist.items)
      .filter((item) => item.product) // Ensure it contains 'product' field
      .map((item) => item.product);

    // If no products exist in the watchlist
    if (productNames.length === 0) {
      return res.status(404).json({
        username,
        message: "No products in the watchlist.",
      });
    }

    // Return the list of product names
    return res.json({
      username,
      products: productNames,
    });
  } catch (err) {
    logger.error(err);
    return res.status(500).json({
      message: "Server error",
      error: err.message,
    });
  }
});

// POST route to add an item (vendor/product) to the watchlist
router.post(
  "/watchlist/update/item",
  authMiddleware,
  body("watchlist").notEmpty().isString(),
  body("product").optional().isString(),
  body("version").optional().isString(),
  validateRequest,
  async (req, res) => {
    logger.info(`POST: /watchlist/item`);
    try {
      const db = await connectDB();
      const { product, watchlist, version } = req.body;
      const authHeader = req.headers.authorization;
      const username = await getUsername(db, authHeader);

      if (!watchlist) {
        return res
          .status(400)
          .json({ success: false, message: "Watchlist name is required" });
      }

      if (product) {
        console.log(product, version, watchlist);
        const cves = await performResolutionBeforeUpdate(
          db,
          username,
          watchlist,
          product,
          version
        );
        await removeProductFromWatchlist(db, username, watchlist, product);
        result = await addProductToWatchlist(
          db,
          username,
          watchlist,
          product,
          version
        );

        console.log(cves);
      } else {
        result[msg] = `Failed to update version( of the product()`;
      }

      // Get updated watchlist data
      const updatedWatchlist = await getWatchlist(db, username);

      return res.status(200).json({
        success: true,
        message: result.message,
        watchlist: updatedWatchlist,
      });
    } catch (err) {
      logger.error(err);
      return res.status(500).json({
        success: false,
        message: `Failed to update version( of the product()`,
      });
    }
  }
);

router.get("/vendors-watchlists", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    // Optional: Sort parameter
    const sortByCVSS = req.query.sort || "lowest-scores-first";

    // Call the controller function to get CVEs for vendors in multiple watchlists
    const result = await getCvesByVendorsInMultipleWatchlists(
      db,
      username,
      page,
      limit,
      sortByCVSS
    );

    // Log request parameters for debugging
    console.log("Vendors watchlists request for username:", username);
    console.log("Page:", page);
    console.log("Limit:", limit);
    console.log("Sort:", sortByCVSS);

    // If the function returned an error
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.message || "Failed to retrieve CVEs",
      });
    }

    // Return successful response
    return res.status(200).json({
      success: true,
      data: result.data,
      vendorsFound: result.vendors, // Changed from vendorsInMultipleWatchlists to vendors
      pagination: {
        page,
        limit,
        total_items: result.pagination.total_items,
        pages: result.pagination.pages,
      },
    });
  } catch (err) {
    console.error("Error in vendors-watchlists route:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message,
    });
  }
});

router.get("/vendors-watchlists", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    // Optional: Sort parameter
    const sortByCVSS = req.query.sort || "lowest-scores-first";

    // Date filtering parameters - set to null by default
    let year = null;
    let month = null;

    // Only parse values if they exist in the query
    if (req.query.year) {
      year = parseInt(req.query.year);
      // Simple validation
      if (isNaN(year)) {
        return res.status(400).json({
          success: false,
          message: "Year must be a valid number",
        });
      }
    }

    if (req.query.month) {
      month = parseInt(req.query.month);
      // Simple validation
      if (isNaN(month) || month < 1 || month > 12) {
        return res.status(400).json({
          success: false,
          message: "Month must be a number between 1 and 12",
        });
      }
    }

    // Call the controller function
    const result = await getCvesByVendorsInMultipleWatchlists(
      db,
      username,
      page,
      limit,
      sortByCVSS,
      year,
      month
    );

    // Log request parameters
    console.log("Vendors watchlists request for username:", username);
    console.log("Page:", page);
    console.log("Limit:", limit);
    console.log("Sort:", sortByCVSS);
    if (year !== null) console.log("Year:", year);
    if (month !== null) console.log("Month:", month);

    // If the function returned an error
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.message || "Failed to retrieve CVEs",
      });
    }

    // Build response object
    const response = {
      success: true,
      data: result.data,
      vendorsFound: result.vendors,
      pagination: result.pagination,
    };

    // Only include filters if they were applied
    if (result.filters) {
      response.filters = result.filters;
    }

    // Return successful response
    return res.status(200).json(response);
  } catch (err) {
    console.error("Error in vendors-watchlists route:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message,
    });
  }
});

router.get("/fixable-cves", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    // Call the controller function
    const result = await getFixableCves(db, username);

    // Return response
    return res.status(result.success ? 200 : 400).json(result);
  } catch (err) {
    console.error("Error in fixable-cves route:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message,
    });
  }
});

// Route to get all products and vendors from the user's watchlists
router.get("/watchlist/products-vendors", authMiddleware, async (req, res) => {
  try {
    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    logger.info(`GET: /watchlist/products-vendors`);
    const productsAndVendors = await getWatchlistProductsAndVendors(
      db,
      username
    );

    res.json({
      username,
      ...productsAndVendors,
    });
  } catch (err) {
    logger.error(err);
    return res
      .status(500)
      .json({ message: "Server error", error: err.message });
  }
});

module.exports = router;
