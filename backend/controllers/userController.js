const logger = require("../logger");
const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const { createUserModel } = require("../models/users");

const getUsername = async (db, authHeader) => {
    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    const usersCollection = createUserModel(db);
    const user = await usersCollection.findOne({
        _id: new ObjectId(decoded.userId),
    });

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    return user.name
}

module.exports = {
    getUsername
};
