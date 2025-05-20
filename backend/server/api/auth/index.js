const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const mongodb = require("mongodb");
const { createUserModel } = require("../../../models/users");
const router = express.Router();
const connectDB = require("../../../config/db");
const sendEmail = require("../auth/mail");
const authMiddleware = require("../../middleware/auth");
const { ObjectId } = require("mongodb");
const { body, validationResult } = require("express-validator");
const mongoSanitize = require("mongo-sanitize");
let db;

// Establish database connection
connectDB().then((database) => {
  db = database;
});

// Centralized validation schemas
const registerValidationRules = [
  body("name").trim().notEmpty().withMessage("Name is required").escape(),
  body("email").isEmail().withMessage("Invalid email").normalizeEmail(),
  body("password")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/)
    .withMessage("Password must be at least 8 characters long, contain uppercase, lowercase, number, and special character"),
  body("otp").isNumeric().withMessage("OTP must be numeric"),
];

const loginValidationRules = [
  body("email").isEmail().withMessage("Invalid email").normalizeEmail(),
  body("password").notEmpty().withMessage("Password is required"),
];

const resetPasswordValidationRules = [
  body("email").isEmail().withMessage("Invalid email").normalizeEmail(),
  body("otp").isNumeric().withMessage("OTP must be numeric"),
  body("newPassword")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/)
    .withMessage("Password must be at least 8 characters long, contain uppercase, lowercase, number, and special character"),
];

// Centralized validation middleware
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array() });
  }
  req.body = mongoSanitize(req.body);
  next();
};

// Helper function to generate access token
const generateAccessToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET_KEY, { expiresIn: "55m" });
};

// Helper function to generate refresh token
const generateRefreshToken = (userId) => {
  return jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });
};

// Route for registration with email OTP verification
router.post("/register", registerValidationRules, validateRequest, async (req, res) => {
    const { name, email, password, otp } = req.body;

    try {
      const usersCollection = createUserModel(db);
      const existingUser = await usersCollection.findOne({ email });
      if (existingUser) return res.status(400).json({ error: "User already exists" });

      const otpRecord = await db.collection("otps").findOne({ email, otp });
      if (!otpRecord || otpRecord.expiry < Date.now())
        return res.status(400).json({ error: "Invalid or expired OTP" });

      const hashedPassword = await bcrypt.hash(password, 10);
      const refreshToken = generateRefreshToken(email);

      const newUser = {
        name,
        email,
        password: hashedPassword,
        createdAt: new Date(),
        refreshToken,
      };

      const insertResult = await usersCollection.insertOne(newUser);
      await db.collection("otps").deleteOne({ email, otp });
      const accessToken = generateAccessToken(insertResult.insertedId);
      res.status(201).json({ message: "User registered successfully", accessToken, refreshToken });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Server error" });
    }
});

// Route to request OTP for registration
router.post("/request-otp", [body("email").isEmail().withMessage("Invalid email").normalizeEmail()], validateRequest, async (req, res) => {
    const { email } = req.body;
    const otp = crypto.randomInt(100000, 999999).toString();

    try {
      await db.collection("otps").updateOne(
        { email },
        { $set: { otp, expiry: Date.now() + 10 * 60 * 1000 } },
        { upsert: true }
      );

      await sendEmail(email, "Your OTP for Registration", `Your OTP is ${otp}`);
      res.status(200).json({ message: "OTP sent to email" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Server error" });
    }
});

// Route for login
router.post("/login", loginValidationRules, validateRequest, async (req, res) => {
    const { email, password } = req.body;

    try {
      const usersCollection = createUserModel(db);
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(400).json({ error: "Invalid credentials" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

      const accessToken = generateAccessToken(user._id);
      const refreshToken = generateRefreshToken(email);

      await usersCollection.updateOne(
        { _id: user._id },
        { $set: { refreshToken } }
      );

      res.json({ accessToken, refreshToken });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Server error" });
    }
});

// Route to get current user
router.get("/me", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    const usersCollection = createUserModel(db);
    const user = await usersCollection.findOne({
      _id: new ObjectId(decoded.userId),
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({ user });
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(401).json({ error: "Unauthorized: Invalid token" });
  }
});

// Route to refresh access token
router.post("/refresh-token", [body("refreshToken").notEmpty().withMessage("Refresh token is required")], validateRequest, async (req, res) => {
    const { refreshToken } = req.body;

    try {
      const usersCollection = createUserModel(db);

      const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

      const user = await usersCollection.findOne({
        email: decoded.userId,
        refreshToken: refreshToken,
      });

      if (!user) {
        return res.status(403).json({ error: "Invalid refresh token" });
      }

      const newAccessToken = generateAccessToken(user._id);

      res.json({ accessToken: newAccessToken });
    } catch (error) {
      console.error(error);
      return res.status(403).json({ error: "Invalid refresh token" });
    }
});

// Route for logout
router.post("/logout", authMiddleware, async (req, res) => {
  try {
    const usersCollection = createUserModel(db);

    await usersCollection.updateOne(
      { _id: req.userId },
      { $unset: { refreshToken: "" } }
    );

    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

// Existing routes for forgot password and reset password remain the same...
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const otp = crypto.randomInt(100000, 999999).toString();

  try {
    const user = await db.collection("users").findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Email not found" });
    }

    await db.collection("otps").updateOne(
      { email },
      { $set: { otp, expiry: Date.now() + 10 * 60 * 1000 } },
      { upsert: true }
    );

    await sendEmail(email, "OTP for Password Reset", `Your OTP is ${otp}`);
    res.status(200).json({ message: "OTP sent to email" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/reset-password", resetPasswordValidationRules, validateRequest, async (req, res) => {
    const { email, otp, newPassword } = req.body;

    try {
      const otpRecord = await db.collection("otps").findOne({ email, otp });
      if (!otpRecord || otpRecord.expiry < Date.now())
        return res.status(400).json({ error: "Invalid or expired OTP" });

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await db.collection("users").updateOne({ email }, { $set: { password: hashedPassword } });

      res.status(200).json({ message: "Password reset successfully" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Server error" });
    }
});

module.exports = router;