
const logger = require("../logger");

const getTotalCVEs = async (db, username) => {
    try {
      const userWatchlist = await db.collection("watchlist").findOne({ username });
  
      if (!userWatchlist || !userWatchlist.watchlists) return 0;
  
      const products = [];
      const vendors = [];
  
      userWatchlist.watchlists.forEach((watchlist) => {
        watchlist.items.forEach((item) => {
          if (item.product) products.push(item.product);
          if (item.vendor) vendors.push(item.vendor);
        });
      });
  
      if (products.length === 0 && vendors.length === 0) return 0;
  
      const pipeline = [
        {
          $match: {
            $or: [
              { "cpe.product": { $in: products } },
              { "cpe.vendor": { $in: vendors } },
            ],
          },
        },
        { $count: "totalCVEs" },
      ];
  
      const result = await db.collection("unified_cves").aggregate(pipeline).toArray();
      return result.length > 0 ? result[0].totalCVEs : 0;
  
    } catch (error) {
      console.error("Error getting total CVEs:", error);
      return 0;
    }
  };
  

  const getPatchableCVEs = async (db, username) => {
    try {
      const userWatchlist = await db.collection("watchlist").findOne({ username });
  
      if (!userWatchlist || !userWatchlist.watchlists) return 0;
  
      const products = [];
      const vendors = [];
  
      userWatchlist.watchlists.forEach((watchlist) => {
        watchlist.items.forEach((item) => {
          if (item.product) products.push(item.product);
          if (item.vendor) vendors.push(item.vendor);
        });
      });
  
      if (products.length === 0 && vendors.length === 0) return 0;
  
      const pipeline = [
        {
          $match: {
            $or: [
              { "cpe.product": { $in: products } },
              { "cpe.vendor": { $in: vendors } },
            ],
            patch_url: { $exists: true, $ne: [] }, // Only count if patches exist
          },
        },
        { $count: "patchableCVEs" },
      ];
  
      const result = await db.collection("unified_cves").aggregate(pipeline).toArray();
      return result.length > 0 ? result[0].patchableCVEs : 0;
  
    } catch (error) {
      console.error("Error getting patchable CVEs:", error);
      return 0;
    }
  };
  

  
  const getHighRiskCVEs = async (db, username) => {
    try {
      const userWatchlist = await db.collection("watchlist").findOne({ username });
  
      if (!userWatchlist || !userWatchlist.watchlists) return 0;
  
      const products = [];
      const vendors = [];
  
      userWatchlist.watchlists.forEach((watchlist) => {
        watchlist.items.forEach((item) => {
          if (item.product) products.push(item.product);
          if (item.vendor) vendors.push(item.vendor);
        });
      });
  
      if (products.length === 0 && vendors.length === 0) return 0;
  
      const pipeline = [
        {
          $match: {
            $or: [
              { "cpe.product": { $in: products } },
              { "cpe.vendor": { $in: vendors } },
            ],
            cvss_score: { $gt: 8.0 }, // High-risk CVEs (CVSS > 8.0)
          },
        },
        { $count: "highRiskCVEs" },
      ];
  
      const result = await db.collection("unified_cves").aggregate(pipeline).toArray();
      return result.length > 0 ? result[0].highRiskCVEs : 0;
  
    } catch (error) {
      console.error("Error getting high-risk CVEs:", error);
      return 0;
    }
  };

    module.exports = {
        getTotalCVEs,
        getPatchableCVEs,
        getHighRiskCVEs,
      };
