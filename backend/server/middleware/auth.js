const jwt = require('jsonwebtoken');
const mongoSanitize = require('mongo-sanitize');
const escapeHtml = require('escape-html');

const authMiddleware = (req, res, next) => {
    const secretKey = process.env.JWT_SECRET_KEY;

    // Check if the Authorization header is present
    const token = req.headers['authorization']?.split(' ')[1]; // Get token from Authorization header

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, secretKey);
        req.userId = escapeHtml(mongoSanitize(decoded.userId));

        // Call the next middleware or route handler
        next();
    } catch (error) {
        console.error('JWT Verification Error:', error);
        return res.status(401).json({ message: 'Unauthorized: Invalid token' });
    }
};

module.exports = authMiddleware;