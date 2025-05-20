const { createUnifiedModel } = require("../models/CVE");
const logger = require("../logger");
const { createCVEModel } = require("../models/CVE");
const semver = require("semver");



const getCriticalProducts = async (db, viewMore) => {
    try {
      const currentDate = new Date();
      const oneYearAgo = new Date();
      oneYearAgo.setFullYear(currentDate.getFullYear() - 1); // Get data from last 1 year
  
      const pipeline = [
        {
          $match: {
            "cvss_score": { $gte: 7 }, // CVSS ≥ 7 (Critical)
            "published_at": { $gte: oneYearAgo, $lte: currentDate } // Only last 1 year
          }
        },
        {
          $match: {
            "vulnerable_cpe": { $exists: true, $ne: [] } // Ensure CPE exists and is not empty
          }
        },
        {
          $project: {
            product_name: { 
              $arrayElemAt: [{ $split: [{ $arrayElemAt: ["$vulnerable_cpe", 0] }, ":"] }, 4] 
            }, // Extract product name from CPE
            description: 1,
            cvss_score: 1,
            published_at: 1
          }
        },
        {
          $match: {
            product_name: { $ne: "n/a" } // Exclude "n/a"
          }
        },
        {
          $group: {
            _id: "$product_name",
            description: { $first: "$description" },
            cvss_score: { $max: "$cvss_score" }, // Highest CVSS score for each product
            cve_count: { $sum: 1 }, // Count CVEs for each product
            latest_date: { $max: "$published_at" } // Most recent CVE date
          }
        },
        { $sort: { cvss_score: -1, latest_date: -1 } }, // Sort by highest CVSS score, then date
        { $limit: 30 }, // Get top 30 products based on CVSS score and date
        {
          $project: {
            _id: 0,
            product: "$_id",
            description: 1,
            cvss_score: 1,
            cve_count: 1,
            latest_date: 1
          }
        }
      ];
  
      const result = await db.collection("unified_cves").aggregate(pipeline).toArray();
  
      if (result.length === 0) {
        return { message: "No critical products found in the past year." };
      }
  
      if (viewMore) {
        return { 
          remaining_list: result.slice(3), // Return 4th to 30th (from index 3 onward)
          total: result.length // Total count of available products
        };
      } else {
        return {
          top_3: result.slice(0, 3), // Return the top 3 based on highest CVSS scores
          total: result.length // Total count of available products
        };
      }
    } catch (error) {
      console.error(error);
      throw new Error("Error fetching critical products");
    }
  };


  const getRecentProducts = async (db, viewMore) => {
    try {
      const currentDate = new Date();
      const oneYearAgo = new Date();
      oneYearAgo.setFullYear(currentDate.getFullYear() - 1); // Get data from 1 year ago
  
      const pipeline = [
        {
          $match: {
            "published_at": { $gte: oneYearAgo, $lte: currentDate }, // 1-year range
            "vulnerable_cpe": { $exists: true, $ne: [] } // Ensure CPE exists and is not empty
          }
        },
        { $unwind: "$vulnerable_cpe" }, // Flatten the CPE array
        {
          $project: {
            product: { 
              $arrayElemAt: [{ $split: ["$vulnerable_cpe", ":"] }, 4] 
            }, // Extract product name from CPE string
            description: 1,
            published_at: 1
          }
        },
        {
          $match: {
            "product": { $ne: "n/a" } // Exclude "n/a" products
          }
        },
        {
          $group: {
            _id: "$product", // Group by product name
            description: { $first: "$description" }, // Take the first available description
            cve_count: { $sum: 1 }, // Count CVEs for each product
            latest_date: { $max: "$published_at" } // Get the most recent CVE for that product
          }
        },
        { $sort: { latest_date: -1 } }, // Sort by most recent CVE first
        { $limit: 30 }, // Get top 30 products based on latest CVE date
        {
          $project: {
            _id: 0,
            product: "$_id",
            description: 1,
            cve_count: 1,
            latest_date: 1
          }
        }
      ];
  
      const result = await db.collection("unified_cves").aggregate(pipeline).toArray();
  
      if (result.length === 0) {
        return { message: "No recent products found in the past year." };
      }
  
      if (viewMore) {
        return {
          remaining_list: result.slice(3), // Return 4th to 30th (from index 3 onward)
          total: result.length
        };
      } else {
        return {
          top_3: result.slice(0, 3), // Return the top 3 most recent products
          total: result.length
        };
      }
    } catch (error) {
      console.error(error);
      throw new Error("Error fetching recent products");
    }
  };

  const getMonthlyCVEsForProduct = async (db, product) => {
    try {
      const endDate = new Date();
      const startDate = new Date();
      startDate.setFullYear(endDate.getFullYear() - 1);
  
      const pipeline = [
        {
          $match: {
            "published_at": { $gte: startDate, $lte: endDate },
            "vulnerable_cpe": { $regex: `:${product}:`, $options: "i" } // Match product in CPE string
          }
        },
        {
          $project: {
            month: { $month: "$published_at" },
            product_name: { 
              $arrayElemAt: [{ $split: [{ $arrayElemAt: ["$vulnerable_cpe", 0] }, ":"] }, 4] 
            } // Extract product name
          }
        },
        {
          $group: {
            _id: { month: "$month" },
            cve_count: { $sum: 1 }
          }
        },
        { $sort: { "_id.month": -1 } } // Sort by recent months first
      ];
  
      const result = await db.collection("unified_cves").aggregate(pipeline).toArray();
  
      // Ensure all months are included with 0 count if missing
      const monthlyCVEMap = new Map(result.map(entry => [entry._id.month, entry.cve_count]));
  
      const completeResult = [];
      for (let i = 0; i < 12; i++) {
        const date = new Date();
        date.setMonth(date.getMonth() - i);
        const month = date.getMonth() + 1;
  
        completeResult.push({
          month: i + 1, // Most recent month is 1
          cve_count: monthlyCVEMap.get(month) || 0
        });
      }
  
      return completeResult;
    } catch (error) {
      console.error(error);
      throw new Error("Error fetching monthly CVEs for product");
    }
  };
  
  const getCVEDataForProduct = async (db, product) => {
    try {
      const endDate = new Date();
      const startDate = new Date();
      startDate.setFullYear(endDate.getFullYear() - 1);
  
      const pipeline = [
        {
          $match: {
            "published_at": { $gte: startDate, $lte: endDate },
            "vulnerable_cpe": { $regex: `:${product}:`, $options: "i" } // Match product in CPE string
          }
        },
        {
          $project: {
            _id: 0,
            cve_id: 1,
            description: 1,
            exploited_rate: {
              $switch: {
                branches: [
                  { case: { $gte: ["$cvss_score", 9] }, then: "High" },
                  { case: { $gte: ["$cvss_score", 7] }, then: "Medium" }
                ],
                default: "Low"
              }
            },
            product_name: { 
              $arrayElemAt: [{ $split: [{ $arrayElemAt: ["$vulnerable_cpe", 0] }, ":"] }, 4] 
            } // Extract product name directly in aggregation
          }
        },
        { $sort: { published_at: -1 } }
      ];
  
      const result = await db.collection("unified_cves").aggregate(pipeline).toArray();
      return result;
    } catch (error) {
      console.error(error);
      throw new Error("Error fetching CVEs for product");
    }
  };
  
  
  module.exports = {
    getCriticalProducts,
    getRecentProducts,
    getMonthlyCVEsForProduct,
    getCVEDataForProduct
  };


