// require('dotenv').config();
// require("./services/cronJobService");
// const { updateSearchCollection } = require("./services/searchService");
const express = require("express");
const logger = require("./logger");
const helmet = require("helmet");
const mongoSanitize = require("mongo-sanitize");
const escapeHtml = require("escape-html");
const connectDB = require("./config/db");
const dbIndexes = require("./config/dbIndexes");
const cveRoutes = require("./routes/cveRoutes");
const cron = require("node-cron"); // Import cron
const authRoutes = require("./server/api/auth");
const watchlistRoutes = require("./routes/watchlistRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const auditRoutes = require("./routes/auditRoutes");
const slowDown = require('express-slow-down');
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const {
  extractVendorWithMetadata,
  parseUpdates,
} = require("./services/watchlistService");

const app = express();
const PORT = process.env.PORT || 3000;

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 45,
  message: "Too many attempts, please try again after 15 minutes.",
});

const strictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, try again later.",
});

const looseLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 450,
  message: "Too many requests from this IP, try again later.",
});

const speedLimiter = slowDown({
  windowMs: 5 * 60 * 1000,
  delayAfter: 100,
  delayMs:()=> 700,
});

app.use(helmet({contentSecurityPolicy: false}));

app.use(express.json());

app.use(express.urlencoded({extended:true}))

app.use(
  cors({
    origin: process.env.FRONTEND || "http://localhost:3000",
    // origin: "http://localhost:5173",
    // origin: "http://dccveengine-vm.eastus.cloudapp.azure.com",
  })
);

// Sanitize & Escape All Inputs Middleware
app.use((req, res, next) => {
  if (req.body) {
    for (let key in req.body) {
      req.body[key] = escapeHtml(mongoSanitize(req.body[key]));
    }
  }
  if (req.query) {
    for (let key in req.query) {
      req.query[key] = escapeHtml(mongoSanitize(req.query[key]));
    }
  }
  if (req.params) {
    for (let key in req.params) {
      req.params[key] = escapeHtml(mongoSanitize(req.params[key]));
    }
  }
  next();
});


(async () => {
  try {
    const db = await connectDB();
    // Set up database indexes for optimized queries
    await dbIndexes();
    app.listen(PORT, () => {
      logger.info(`Application initialized successfully on port ${PORT}`);
    });
  } catch (error) {
    logger.error("Error initializing the application:");
    logger.error(error);
  }

  // API

  app.set("server.timeout", 300000);
  app.use("/api/auth", authLimiter, authRoutes);
  app.use("/api/cve", strictLimiter, cveRoutes);
  app.use("/api/dashboard", strictLimiter, dashboardRoutes);
  app.use("/api", strictLimiter, watchlistRoutes);
  app.use("/api/audit", strictLimiter, auditRoutes);

  app.use("/api", speedLimiter, looseLimiter);
})();
