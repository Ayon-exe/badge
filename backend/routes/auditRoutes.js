const express = require("express");
const router = express.Router();
const connectDB = require("../config/db");
const multer = require('multer');
const logger = require("../logger");
const { generateAuditPDF } = require("../utils/pdfGenerator");
const path = require('path');
const fs = require('fs');
const { generateProductPDFsZip } = require("../utils/pdfGenerator");
const authMiddleware = require("../server/middleware/auth");
const { getUsername } = require("../controllers/userController");
const {
  
  generateAuditKey,
  getAuditData,
 
  uploadSoftwareAudit,
 
} = require("../controllers/auditControllers");
const { get } = require("mongoose");

const upload = multer({ 
    dest: 'uploads/',
    limits: {
      fileSize: 5 * 1024 * 1024 // 5MB limit
    }
  });
  
  router.post("/audit/upload", upload.single('csvFile'), async (req, res) => {
    try {
      const db = await connectDB();
      const { userID, key } = req.body;
  
      logger.info(`POST: /audit/upload for user ${userID}`);
  
      if (!req.file) {
        return res.status(400).json({
          message: "No CSV file uploaded"
        });
      }
  
      const result = await uploadSoftwareAudit(db, userID, key, req.file);
  
      res.status(201).json({
        message: "Software audit data uploaded successfully",
        ...result
      });
    } catch (err) {
      logger.error(`Audit upload error: ${err.message}`);
      return res
        .status(500)
        .json({ message: "Server error", error: err.message });
    }
  });
  
  router.post("/audit/generate-key", async (req, res) => {
    try {
      const db = await connectDB();
      const { userID } = req.body;
      
      logger.info(`POST: /audit/generate-key for user ${userID}`);
      
      if (!userID) {
        return res.status(400).json({
          success: false,
          message: "User ID is required"
        });
      }
      
      const result = await generateAuditKey(db, userID);
      
      res.status(200).json({
        message: "Audit key generated successfully",
        ...result
      });
    } catch (err) {
      logger.error(`Generate key error: ${err.message}`);
      return res
        .status(500)
        .json({ success: false, message: err.message || "Server error" });
    }
  });
  
  // Route to get audit data using a key
  router.post("/audit/get-data", async (req, res) => {
    try {
      const db = await connectDB();
      const { key } = req.body;
      
      logger.info(`POST: /audit/get-data with key ${key ? key.substring(0, 4) + '...' : 'undefined'}`);
      
      if (!key) {
        return res.status(400).json({
          success: false,
          message: "Audit key is required"
        });
      }
      
      const result = await getAuditData(db, key);
      
      res.status(200).json({
        message: "Audit data retrieved successfully",
        ...result
      });
    } catch (err) {
      logger.error(`Get audit data error: ${err.message}`);
      return res
        .status(500)
        .json({ success: false, message: err.message || "Server error" });
    }
  });

  router.post("/audit/generate-pdf", async (req, res) => {
    try {
      const db = await connectDB();
      const { key } = req.body;
      
      logger.info(`POST: /audit/generate-pdf with key ${key ? key.substring(0, 4) + '...' : 'undefined'}`);
      
      if (!key) {
        return res.status(400).json({
          success: false,
          message: "Audit key is required"
        });
      }
      
      // Get the audit data first
      const result = await getAuditData(db, key);
      
      if (!result.success) {
        return res.status(404).json({
          success: false,
          message: "Could not find audit data"
        });
      }
      
      // Generate the PDF from the audit data
      generateAuditPDF(result.data, (pdfBuffer) => {
        // Set response headers for PDF download
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=audit-report-${result.data._id}.pdf`);
        res.setHeader('Content-Length', pdfBuffer.length);
        
        // Send the PDF
        res.send(pdfBuffer);
      });
      
    } catch (err) {
      logger.error(`Generate PDF error: ${err.message}`);
      return res
        .status(500)
        .json({ success: false, message: err.message || "Server error" });
    }
  });

  router.post("/audit/generate-products-zip", async (req, res) => {
 
  req.setTimeout(300000); // 5 minutes (300,000 ms)
  res.setTimeout(300000); // 5 minutes (300,000 ms)
  
  try {
    const db = await connectDB();
    const { key } = req.body;
    
    logger.info(`POST: /audit/generate-products-zip with key ${key ? key.substring(0, 4) + '...' : 'undefined'}`);
    
    if (!key) {
      return res.status(400).json({
        success: false,
        message: "Audit key is required"
      });
    }
    
    // Get the audit data first
    const result = await getAuditData(db, key);
    
    if (!result.success) {
      return res.status(404).json({
        success: false,
        message: "Could not find audit data"
      });
    }
    
    // Create a temporary file path for the zip
    const zipFileName = `product-reports-${result.data._id}.zip`;
    const zipFilePath = path.join(__dirname, '..', 'temp', zipFileName);
    
    // Ensure the temp directory exists
    const tempDir = path.join(__dirname, '..', 'temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    // Add a promise wrapper around the PDF generation
    await new Promise((resolve, reject) => {
      try {
        generateProductPDFsZip(result.data, zipFilePath, () => {
          resolve();
        });
      } catch (err) {
        logger.error(`Error in PDF generation: ${err.message}`);
        reject(err);
      }
    });
    
    // Stream the file to the client
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename=${zipFileName}`);
    
    const fileStream = fs.createReadStream(zipFilePath);
    fileStream.pipe(res);
    
    // Clean up the file after it's sent
    fileStream.on('end', () => {
      try {
        if (fs.existsSync(zipFilePath)) {
          fs.unlinkSync(zipFilePath);
        }
      } catch (cleanupErr) {
        logger.error(`Error cleaning up zip file: ${cleanupErr.message}`);
      }
    });
    
    // Handle file stream errors
    fileStream.on('error', (streamErr) => {
      logger.error(`Stream error: ${streamErr.message}`);
      if (!res.headersSent) {
        return res.status(500).json({ 
          success: false, 
          message: "Error streaming the zip file" 
        });
      }
    });
    
  } catch (err) {
    logger.error(`Generate Products ZIP error: ${err.message}`);
    return res
      .status(500)
      .json({ success: false, message: err.message || "Server error" });
  }
});
  
  
  
  module.exports = router;
  