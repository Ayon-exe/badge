const logger = require("../logger");
const express = require("express");
const router = express.Router();
const {
    getCriticalProducts,
    getRecentProducts,
    getMonthlyCVEsForProduct,
    getCVEDataForProduct

}  = require("../controllers/cveController");
const connectDB = require("../config/db");
const authMiddleware = require("../server/middleware/auth");

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
      
      
      
      module.exports = router;
      