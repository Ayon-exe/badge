const winston = require("winston");

// defining logger structure
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ level, message, timestamp }) => {
      return `${timestamp} [${level}]: ${message}`;
    }),
  ),
  transports: [
    new winston.transports.Console(),
    // new winston.transports.File({ filename: "app.log" }),
  ],
});

module.exports = logger;
