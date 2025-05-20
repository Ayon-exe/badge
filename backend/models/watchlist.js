const { ObjectId } = require("mongodb");

const watchlistSchema = {
  _id: ObjectId,
  username: { type: String, required: true },
  watchlists: { type: [Object], default: [] },
};

const createWatchlistModel = (db) => {
  return db.collection("watchlist");
};

const createWatchlistLogsModel = (db) => {
  return db.collection("watchlist_logs");
};

module.exports = {
  createWatchlistModel,
  watchlistSchema,
createWatchlistLogsModel,
};
