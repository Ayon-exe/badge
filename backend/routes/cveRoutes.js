const logger = require("../logger");
const express = require("express");
const router = express.Router();
const connectDB = require("../config/db");
const authMiddleware = require("../server/middleware/auth");
const {
  getBoxDataStats,
  getAttackVectorStats,
  filterByCVEId,
  getMatchedVendorsAndProducts,
  getExploitedStats,
  getTopVendorStats,
  getTopProductStats,
  generalSearch,
  getCveStatisticsByVendor,
  getCvesByVendorAndYear,
  getCVEStats,
  getFixesStats,
  getTopVendorByFixes,
  getCWEStats,
  getCWEStatsFast,
  getCvssScoreRanges,
  getCvssScoreRangesFast,
  getProductVersions,
  getProductVersionVulnerabilities,
  getVersionDetails,
  getFilteredVendorVulnerabilities,
  getFilteredProductVulnerabilities,
  getTopVendorByYear,
  getAverageCVEsPerYear,
  getHighRiskVendorCount,
  getTotalVendors,
  getProductWithMostCVEs,
  getTopProductByFixes,
  getAverageProductCVEsPerYear,
  getTotalProducts,
  getHighRiskProductCount,
  getDailyCVEsForProduct,
  getWeeklyCVEsForProduct,
  getMonthlyCVEsForProduct,
  getCVEDataForProduct,
  getCriticalProducts,
  getRecentProducts,
  getTopSevereCVEs,
  getTotalVulnerabilities,
  getUniqueVendors,
  getAlphabeticalVendors,
  getAlphabeticalProducts,
  updateProductsBoxDataStats,
  getVendorStats,
  getFilteredCves,
  getProductsBoxDataStats,
  getVendorsBoxDataStats,
  generalSearchProductVersion,
} = require("../controllers/cveController");

// Add route to get unique vendors
router.get("/vendors", async (req, res) => {
  try {
    const db = await connectDB();
    const vendors = await getUniqueVendors(db);
    logger.info("/vendors");
    res.json(vendors);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});
// Route to filter by CVE ID (protected route)
router.get("/cveid/:id", async (req, res) => {
  try {
    const db = await connectDB();
    const cve = await filterByCVEId(db, req.params.id);
    if (cve) {
      res.json(cve);
    } else {
      res.status(404).json({ message: "CVE not found" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get CVE statistics by vendor (protected route)
router.get("/statistics/:vendor", async (req, res) => {
  logger.info(`/statistics/${req.params}`);
  try {
    const db = await connectDB();
    const { vendor } = req.params;
    const statistics = await getCveStatisticsByVendor(db, vendor);
    res.json(statistics);
  } catch (err) {
    logger.error(err); // Log the error for debugging
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get CVEs by vendor and year (protected route)
router.get("/vendor/:vendor/year/:year", async (req, res) => {
  try {
    const db = await connectDB();
    const { vendor, year } = req.params;
    logger.info(`/vendor/${vendor}/year/${year}`);
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;

    logger.debug(`vendor: ${vendor}`);
    logger.debug(`year: ${year}`);
    logger.debug(`page: ${page}`);
    logger.debug(`limit: ${limit}`);

    const cves = await getCvesByVendorAndYear(db, vendor, year, page, limit);
    res.json(cves);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get CWE statistics (public route)
router.get("/weaknesses/stats", async (req, res) => {
  logger.info("/weaknesses/stats");
  try {
    const vendor = req.query.vendor;
    const db = await connectDB();
    const stats = await getCWEStats(db, vendor);
    res.json(stats);
  } catch (err) {
    logger.error(err); // Log the error for debugging
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get CVE statistics (public route)
router.get("/stats", async (req, res) => {
  logger.info("/stats");
  try {
    const db = await connectDB();
    const stats = await getCVEStats(db);
    res.json(stats);
  } catch (err) {
    logger.error(err); // Log the error for debugging
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Autocomplete route (protected route)
router.get("/autocomplete", async (req, res) => {
  logger.info("/autocomplete");
  try {
    const db = await connectDB();
    const query = req.query.q || "";
    if (!query) {
      return res.json({ products: [], vendors: [], cveIds: [] });
    }

    const results = await generalSearch(db, query);
    res.json(results);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});
  
// Autocomplete route (protected route)
router.get("/product/:product/autocomplete", async (req, res) => {
  logger.info("/product/:product/autocomplete");
  try {
    const db = await connectDB();
    const query = req.query.q || "";
    const { product } = req.params;
    if (!query) {
      return res.json({ products: [], vendors: [], cveIds: [] });
    }

    const results = await generalSearchProductVersion(db, product, query);
    res.json(results);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});


router.get("/cvss/stats", async (req, res) => {
  logger.info("/cvss/stats");
  try {
    const vendor = req.query.vendor;
    const db = await connectDB();
    const cvssStats = await getCvssScoreRanges(db, vendor);
    res.json(cvssStats);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/product/:product/versions", async (req, res) => {
  try {
    const db = await connectDB();
    const { product } = req.params;
    logger.info(`/product/${product}/versions`);
    const versions = await getProductVersions(db, product);
    // console.log(versions)
    if (versions.length === 0) {
      res.status(404).json({ message: "No versions found for this product" });
    } else {
      res.json(versions);
    }
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get vulnerabilities for a specific product and version (protected route)
router.get("/product/:product/version/:version/vulnerabilities",async (req, res) => {
    try {
      const db = await connectDB();
      const { product, version } = req.params;
      logger.info(`/product/${product}/version/${version}/vulnerabilities`);
      const vulnerabilities = await getProductVersionVulnerabilities(
        db,
        product,
        version
      );
      if (vulnerabilities.length === 0) {
        res.status(404).json({
          message: "No vulnerabilities found for this product and version",
        });
        logger.info({
          message: "No vulnerabilities found for this product and version",
        });
      } else {
        res.json(vulnerabilities);
      }
    } catch (err) {
      logger.error(err);
      res.status(500).json({ message: "Server error", error: err.message });
    }
  }
);

// Route to get version details (protected route)
router.get("/product/:product/version/:version/details", async (req, res) => {
  try {
    const db = await connectDB();
    const { product, version } = req.params;
    logger.info(`/product/${product}/version/${version}/details`);
    const details = await getVersionDetails(db, product, version);
    if (details) {
      res.json(details);
    } else {
      res.status(404).json({ message: "Version details not found" });
    }
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/product/:product/version/:version/filtered", async (req, res) => {
  try {
    const db = await connectDB();
    // Decode the URL-encoded product name and version
    const product = decodeURIComponent(req.params.product);
    const version = decodeURIComponent(req.params.version);
    logger.info(`/product/${product}/version/${version}/filtered`);
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;

    const filters = {
      year: req.query.year,
      month: req.query.month,
      minCvss: req.query.minCvss,
      sortBy: req.query.sortBy,
    };

    const result = await getFilteredProductVulnerabilities(
      db,
      product,
      version,
      page,
      limit,
      filters
    );

    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route for filtered vendor vulnerabilities
router.get("/vendor/:vendor/year/:year/filtered", async (req, res) => {
  try {
    const db = await connectDB();
    const { vendor, year } = req.params;
    logger.info(`/vendor/${vendor}/year/${year}/filtered`);
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const filters = {
      month: req.query.month,
      minCvss: req.query.minCvss,
      sortBy: req.query.sortBy,
    };
    logger.debug(`vendor: ${vendor}`);
    logger.debug(`year: ${year}`);
    logger.debug(`page: ${page}`);
    logger.debug(`limit: ${limit}`);
    logger.debug(`filters: ${filters}`);
    console.debug(filters);

    const result = await getFilteredVendorVulnerabilities(
      db,
      vendor,
      year,
      page,
      limit,
      filters
    );
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/vendors/alphabetical/:letter?", async (req, res) => {
  try {
    const { letter } = req.params;
    logger.info(`/vendors/alphabetical/${letter}?`);
    const db = await connectDB();
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;

    const vendors = await getAlphabeticalVendors(db, letter, page, limit);
    res.json(vendors);
  } catch (error) {
    logger.error("Error fetching vendors:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/products/alphabetical/:letter?", async (req, res) => {
  try {
    const { letter } = req.params;
    logger.info(`/products/alphabetical/${letter}?`);
    const db = await connectDB();
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;

    const products = await getAlphabeticalProducts(db, letter, page, limit);
    res.json(products);
  } catch (error) {
    logger.error("Error fetching products:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Route to get fixes statistics (public route)
router.get("/fixes/stats", async (req, res) => {
  logger.info("/fixes/stats");
  try {
    const db = await connectDB();
    const vendor = req.query.vendor;
    const stats = await getFixesStats(db, vendor);
    res.json(stats);
  } catch (err) {
    logger.error(err); // Log the error for debugging
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get fixes statistics (public route)
router.get("/topVendor/stats", async (req, res) => {
  logger.info("/topVendor/stats");
  try {
    const db = await connectDB();
    const stats = await getTopVendorStats(db);
    res.json(stats);
  } catch (err) {
    logger.error(err); // Log the error for debugging
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get fixes statistics (public route)
router.get("/topProduct/stats", async (req, res) => {
  logger.info("/topProduct/stats");
  try {
    const db = await connectDB();
    const stats = await getTopProductStats(db);
    res.json(stats);
  } catch (err) {
    logger.error(err); // Log the error for debugging
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get fixes statistics (public route)
router.get("/exploited/stats", async (req, res) => {
  logger.info("/exploited/stats");
  try {
    const db = await connectDB();
    const stats = await getExploitedStats(db);
    res.json(stats);
  } catch (err) {
    logger.error(err); // Log the error for debugging
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get attack vector statistics (public route)
router.get("/attackVector/stats", async (req, res) => {
  logger.info("/attackVector/stats");
  try {
    const db = await connectDB();
    const vendor = req.query.vendor;
    const stats = await getAttackVectorStats(db, vendor);
    res.json(stats);
  } catch (err) {
    logger.error(err); // Log the error for debugging
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get top vendor by year (public route)
router.get("/top-vendor", async (req, res) => {
  logger.info("/top-vendor");
  try {
    const db = await connectDB();
    const topVendor = await getTopVendorByYear(db);
    res.json(topVendor);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get top vendor fixes by year (public route)
router.get("/top-vendorfixes", async (req, res) => {
  logger.info("/top-vendorfixes");
  try {
    const db = await connectDB();
    const year = parseInt(req.params.year);
    const topVendor = await getTopVendorByFixes(db, year);
    res.json(topVendor);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get the average CVE count per year (public route)
router.get("/average-cves", async (req, res) => {
  logger.info("/average-cves");
  try {
    const db = await connectDB();
    const avgCVE = await getAverageCVEsPerYear(db);
    res.json(avgCVE);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get the count of vendors with CVSS > 7 (public route)
router.get("/highrisk-vendors", async (req, res) => {
  logger.info("/highrisk-vendors");
  try {
    const db = await connectDB();
    const vendorCount = await getHighRiskVendorCount(db);
    res.json(vendorCount);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get the total number of vendors (public route)
router.get("/total-vendors", async (req, res) => {
  logger.info("/total-vendors");
  try {
    const db = await connectDB();
    const totalVendors = await getTotalVendors(db);
    res.json(totalVendors);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get the product with the most vulnerabilities in a year (public route)
router.get("/top-product", async (req, res) => {
  logger.info("/top-product");
  try {
    const db = await connectDB();
    const year = parseInt(req.params.year);
    const topProduct = await getProductWithMostCVEs(db, year);
    res.json(topProduct);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// **Route to get the product with the most fixes in a year (public route)
router.get("/top-productfixes", async (req, res) => {
  logger.info("/top-productfixes");
  try {
    const db = await connectDB();
    const year = parseInt(req.params.year);
    const topProduct = await getTopProductByFixes(db, year);
    res.json(topProduct);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get the average CVE count per year for products
router.get("/average-productcves", async (req, res) => {
  logger.info("/average-productcves");
  try {
    const db = await connectDB();
    const avgCVE = await getAverageProductCVEsPerYear(db);
    res.json(avgCVE);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get the total number of products (public route)
router.get("/total-products", async (req, res) => {
  logger.info("/total-products");
  try {
    const db = await connectDB();
    const totalProducts = await getTotalProducts(db);
    res.json(totalProducts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get the total number of high-risk products
router.get("/highrisk-products", async (req, res) => {
  logger.info("/highrisk-products");
  try {
    const db = await connectDB();
    const productCount = await getHighRiskProductCount(db);
    res.json(productCount);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/vendorStats", async (req, res) => {
  logger.info("/vendorStats endpoint called");
  try {
    const db = await connectDB();
    const result = await getVendorsBoxDataStats(db);

    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/productStats", async (req, res) => {
  logger.info("/productStats");
  try {
    const db = await connectDB();
    const result = await getProductsBoxDataStats(db);
    return res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get fixes statistics (public route)
router.get("/boxData/stats", async (req, res) => {
  logger.info("/boxData/stats");
  try {
    const db = await connectDB();
    const vendor = req.query.vendor;
    const stats = await getBoxDataStats(db, vendor);
    res.json(stats);
  } catch (err) {
    logger.error(err); // Log the error for debugging
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/vendor/:vendor/stats", async (req, res) => {
  const vendor = req.params.vendor;
  logger.info(`GET /vendor/${vendor}/stats`);
  try {
    const db = await connectDB();
    const stats = await getVendorStats(db, vendor);
    res.json(stats);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Route to get filtered CVEs
router.post("/filter", async (req, res) => {
  try {
    const filters = req.body.filters; // Expect an array, e.g. [ "apple", "microsoft" ]
    logger.info(`Received filters: ${JSON.stringify(filters)}`);
    const db = await connectDB();
    const result = await getFilteredCves(db, filters);
    res.json(result);
  } catch (err) {
    logger.error("Error in /filter route:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/daily-cves", async (req, res) => {
  logger.info("/daily-cves"); 
  try {
    const db = await connectDB();
    const { year, month, product } = req.query;

    if (!year || !month || !product) {
      return res.status(400).json({ message: "Year, month, and product are required" });
    }

    const yearNumber = parseInt(year, 10);
    const monthNumber = parseInt(month, 10);

    if (isNaN(yearNumber) || yearNumber < 2014 || yearNumber > new Date().getFullYear()) {
      return res.status(400).json({ message: "Invalid year. Use a value from 2014 to the current year." });
    }
    if (isNaN(monthNumber) || monthNumber < 1 || monthNumber > 12) {
      return res.status(400).json({ message: "Invalid month. Use values between 1 and 12." });
    }

    const cveData = await getDailyCVEsForProduct(db, yearNumber, monthNumber, product);
    res.json(cveData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/critical-products", async (req, res) => {
  logger.info("/critical-products");
  try {
    const db = await connectDB();
    const viewMore = req.query.viewMore === "true"; 
    const criticalProducts = await getCriticalProducts(db, viewMore);
    res.json(criticalProducts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/rec-products", async (req, res) => {
  logger.info("/rec-products");
  try {
    const db = await connectDB();
    const { viewMore } = req.query; 
    const criticalProducts = await getRecentProducts(db, viewMore === "true");
    if (criticalProducts) {
      res.json(criticalProducts);
    } else {
      res.status(404).json({ message: "No critical products found." });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/top-severe-cves", async (req, res) => {
  logger.info("/top-severe-cves");

  const vendor = req.query.vendor; 
  if (!vendor) {
    return res.status(400).json({ message: "Vendor parameter is required" });
  }

  try {
    const db = await connectDB();
    const severeCVEs = await getTopSevereCVEs(db, vendor);
    res.json(severeCVEs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});
router.get("/total-vulnerabilities", async (req, res) => {
  logger.info("/total-vulnerabilities");
  
  try {
    const db = await connectDB();
    const totalVulnerabilities = await getTotalVulnerabilities(db);
    res.json(totalVulnerabilities);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/weekly-cves", async (req, res) => {
  logger.info("/weekly-cves");
  try {
    const db = await connectDB();
    const { product } = req.query; // Get product from query params

    if (!product) {
      return res.status(400).json({ message: "Product name is required" });
    }

    const cveData = await getWeeklyCVEsForProduct(db, product);
    res.json(cveData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

router.get("/cve-monthcount", async (req, res) => {
  logger.info("/cve-monthcount");
  try {
    const db = await connectDB();
    const { product } = req.query;

    if (!product) {
      return res.status(400).json({ error: "Product name is required" });
    }

    const monthlyCVEData = await getMonthlyCVEsForProduct(db, product);
    res.json(monthlyCVEData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error", message: error.message });
  }
});

router.get("/cve-details", async (req, res) => {
  try {
    const db = await connectDB();
    const { product } = req.query;

    if (!product) {
      return res.status(400).json({ error: "Product name is required" });
    }

    const cveData = await getCVEDataForProduct(db, product);
    res.json(cveData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error", message: error.message });
  }
});

router.get("/cve-barstats", async (req, res) => {
  logger.info("/cve-barstats");
  try {
    const db = await connectDB();
    const { product } = req.query;

    if (!product) {
      return res.status(400).json({ error: "Product name is required" });
    }

    // Fetch both monthly count and CVE details
    const [monthlyCVEData, cveDetails] = await Promise.all([
      getMonthlyCVEsForProduct(db, product),
      getCVEDataForProduct(db, product)
    ]);

    res.json({
      monthly_cve_counts: monthlyCVEData,
      cve_details: cveDetails
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error", message: error.message });
  }
});

// Route to update cached data for products box
router.post("/update-products-box", async (req, res) => {
  logger.info("/update-products-box");
  try {
    const db = await connectDB(); // Connect to the database
    await updateProductsBoxDataStats(db); // Call the function to update the cache
    res.status(200).json({ message: "Products Box Data cache updated successfully." });
  } catch (err) {
    logger.error("Error updating Products Box Data cache:", err);
    res.status(500).json({ message: "Failed to update Products Box Data cache.", error: err.message });
  }
});


router.get("/matched-products-vendors", async (req, res) => {
  try {
    const db = await connectDB();
    const matchedNames = await getMatchedVendorsAndProducts(db);
    res.json({ matched: matchedNames });
  } catch (error) {
    console.error("Error in matching products/vendors", error);
    res.status(500).json({ error: "Server error" });
  }
});





module.exports = router;
