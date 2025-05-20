const { ObjectId } = require('mongodb');

// Define the user schema as a simple object
const userSchema = {
    _id: ObjectId,
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    googleId: {
        type: String,
        unique: true,
    },
    provider: {
        type: String,
        enum: ['local', 'google', 'other'],
        default: 'local',
    },
};

// Create a model for users
const createUserModel = (db) => {
    return db.collection('users');  // Use the native MongoDB driver to access the users collection
};

module.exports = {
    createUserModel,
    userSchema,
};
