const logger = require("../logger");

const getTotalCVEs = async (db, username) => {
  try {
    const userWatchlist = await db
      .collection("watchlist")
      .findOne({ username });

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

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();
    return result.length > 0 ? result[0].totalCVEs : 0;
  } catch (error) {
    console.error("Error getting total CVEs:", error);
    return 0;
  }
};

const getPatchableCVEs = async (db, username) => {
  try {
    const userWatchlist = await db
      .collection("watchlist")
      .findOne({ username });

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
  
    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();
    return result.length > 0 ? result[0].patchableCVEs : 0;
  } catch (error) {
    console.error("Error getting patchable CVEs:", error);
    return 0;
  }
};

const getHighRiskCVEs = async (db, username) => {
  try {
    const userWatchlist = await db
      .collection("watchlist")
      .findOne({ username });

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

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();
    return result.length > 0 ? result[0].highRiskCVEs : 0;
  } catch (error) {
    console.error("Error getting high-risk CVEs:", error);
    return 0;
  }
};

const getVendorsAndProducts = async (db, username) => {
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

  return { vendors, products };
};

const getNewCVEs = async (db, username) => {
  const items = await getVendorsAndProducts(db, username);
  const products = items.products;
  const vendors = items.vendors;
  const now = new Date();
  const hour = new Date(now);
  hour.setHours(now.getHours() - 24);

  const pipeline = [
    {
      $match: {
        $or: [
          { "cpe.product": { $in: products } },
          { "cpe.vendor": { $in: vendors } },
        ],
        tag: 'R', // High-risk CVEs (CVSS > 8.0)
      },
    },
    {
      $project: {
        cve_id: 1,
        cvss_score: 1,
        description: 1,
        "cpe.product": 1,
        published_at: 1,
      },
    },
  ];

  const result = await db
    .collection("unified_cves")
    .aggregate(pipeline)
    .toArray();
  return result;
};

const getWeeklyMonthlyData = async (db, username) => {
  try {
    // Get the current date
    const today = new Date();

    // Get the start of the current week (Sunday)
    const currentWeekStart = new Date(today.setDate(today.getDate() - today.getDay()));

    // Get the end of the current week (Saturday)
    const currentWeekEnd = new Date(currentWeekStart.getTime() + 6 * 24 * 60 * 60 * 1000);

    // Get the start of the previous week (Sunday)
    const previousWeekStart = new Date(currentWeekStart.getTime() - 7 * 24 * 60 * 60 * 1000);

    // Get the end of the previous week (Saturday)
    const previousWeekEnd = new Date(previousWeekStart.getTime() + 6 * 24 * 60 * 60 * 1000);

    console.log(currentWeekStart, currentWeekEnd, previousWeekStart, previousWeekEnd);

    // Aggregating resolved and non-resolved CVEs
    const resolvedCount = await db.collection("resolution_status").aggregate([
      {
        $match: { username },
      },
      {
        $unwind: "$cves",
      },
      {
        $match: { "cves.status": "resolved" },
      },
      {
        $group: {
          _id: "$username",
          count: { $count: {} },
        },
      },
    ]).toArray();

    const nonFixedCount = await db.collection("resolution_status").aggregate([
      {
        $match: {
          username,
        },
      },
      {
        $unwind: "$cves",
      },
      {
        $match: {
          "cves.status": "open",
        },
      },
      {
        $group: {
          _id: "$username",
          count: { $count: {} },
        },
      },
    ]).toArray();

    const cur = await db.collection("resolution_status").aggregate([
      {
        $match: {
          username,
        },
      },
      {
        $unwind: "$cves",
      },
      {
        $match: {
          "cves.status": "resolved",
          "cves.updated_at": { "$gte": currentWeekStart, "$lte": currentWeekEnd },
        },
      },
      {
        $group: {
          _id: "$username",
          count: { $count: {} },
        },
      },
    ]).toArray();

    const prev = await db.collection("resolution_status").aggregate([
      {
        $match: {
          username,
        },
      },
      {
        $unwind: "$cves",
      },
      {
        $match: {
          "cves.status": "resolved",
          "cves.updated_at": { "$gte": previousWeekStart, "$lte": previousWeekEnd },
        },
      },
      {
        $group: {
          _id: "$username",
          count: { $count: {} },
        },
      },
    ]).toArray();

    // Get the new CVEs
    const newCvesCount = await db.collection("unified_cves").countDocuments({
      "published_at": { "$gte": previousWeekStart, "$lte": previousWeekEnd },
    });

    // Get notable fixes (You can adjust the filter criteria based on your definition of 'notable')
    const notableFixes = await db.collection("unified_cves").aggregate([
      {
        $match: {
          "cvss_score": { $gt: 8 }, // Only high severity CVEs as an example
        },
      },
      {
        $project: {
          cve_id: 1,
          cvss_score: 1,
          description: 1,
          "cpe.product": 1,
          "cpe.vendor": 1,
        },
      },
      {
        $limit: 5, // Limit the number of notable fixes to the top 5
      },
    ]).toArray();

    // Format the notable fixes into a user-friendly format
    const formattedNotableFixes = notableFixes.map(fix => ({
      product: fix["cpe.product"] || "Unknown Product",
      issue: `CVSS Score: ${fix.cvss_score} - ${fix.description}`,
    }));

    // Returning the response with notable fixes
    return {
      newCves: newCvesCount.length,
      resolvedCves: resolvedCount.length > 0 ? resolvedCount[0].count : 0,
      nonFixedCves: nonFixedCount.length > 0 ? nonFixedCount[0].count : 0,
      comparisons: {
        lastWeek: `${prev[0]?.count || 0} CVEs Resolved`,
        thisWeek: `${cur[0]?.count || 0} CVEs Resolved`,
      },
      notableFixes: formattedNotableFixes, // Add the notable fixes here
    };
  } catch (err) {
    console.log("Error in getWeeklyMonthlyData:", err);
    return {}; // Return an empty object in case of error
  }
};

const getUpdateData = async (db, username) => {
  const resolvedCount = await db
    .collection("resolution_status")
    .aggregate([
      {
        $match: { username },
      },
      {
        $unwind: "$cves",
      },
      {
        $match: { "cves.status": "resolved" },
      },
    ])
    .toArray();

  const cveIds = resolvedCount.map((item) => item.cves.cve_id);

  const cves = await db
    .collection("unified_cves")
    .find({ _id: { $in: cveIds } })
    .toArray();

  let count = 0;
  const resolvedCves = cves.map((item) => {
    if (item.cpe.length) {
      while (
        item.cpe[count].version === "*" ||
        item.cpe[count].version === "-"
      ) {
        count++;
      }
      product_info =
        item.cpe[count].product +
        `${item.cpe.length > 1 ? " +" + (item.cpe.length - 1) : ""}`;
    }
    return {
      id: item.cve_id,
      product: product_info,
      status: "✅ Fixed",
    };
  });
  const productUpdates = cves.map((item) => ({
    product: item.cpe[0].product,
    version: `${
      item.cpe.length === count ? "updated " : item.cpe[count].version
    } ⬆️ `,
  }));
  const watchlist = await db
    .collection("watchlist")
    .find({ username })
    .toArray();
  const watchlistUpdates = [
    { product: "Google Chrome", status: "📌 Added to Watchlist" },
  ];

  return { resolvedCves, productUpdates, watchlistUpdates };
};

const getResolvedYesterdayCVEs = async (db, username) => {
  try {
    const start = new Date();
    start.setDate(start.getDate() - 1);
    start.setHours(0, 0, 0, 0);

    const end = new Date();
    end.setDate(end.getDate() - 1);
    end.setHours(23, 59, 59, 999);

    const result = await db
      .collection("resolution_status")
      .aggregate([
        { $match: { username } },
        { $unwind: "$cves" },
        {
          $match: {
            "cves.status": "resolved",
            "cves.updated_at": { $gte: start, $lte: end },
          },
        },
        { $count: "resolvedCount" },
      ])
      .toArray();

    return result.length > 0 ? result[0].resolvedCount : 0;
  } catch (error) {
    logger.error("Error getting yesterday's resolved CVEs:", error);
    return 0;
  }
};

const getTodaysActivityData = async (db, username) => {
  const items = await getVendorsAndProducts(db, username);
  const products = items.products;
  const vendors = items.vendors;

  const now = new Date();
  const start = new Date(now.getTime() - 12 * 60 * 60 * 1000);

  const newCves = await db
    .collection("unified_cves")
    .aggregate([
      {
        $match: {
          $or: [
            { "cpe.product": { $in: products } },
            { "cpe.vendor": { $in: vendors } },
          ],
          published_at: { $gte: start, $lte: now },
        },
      },
    ])
    .toArray();

  const resolved = await db
    .collection("resolution_status")
    .aggregate([
      { $match: { username } },
      {
        $project: {
          _id: 1,
          username: 1,
          last_updated: 1,
          cves: {
            $filter: {
              input: "$cves",
              as: "cve",
              cond: { 
                $and: [
                  { $gt: ["$$cve.updated_at", start] }, // Check if updated_at is greater than the timestamp
                  { $eq: ["$$cve.status", "resolved"] } // Check if status is 'resolved'
                ]
              } 
            }
          }
        }
      },
    ])
    .toArray();

  const ignored = await db
    .collection("resolution_status")
    .aggregate([
      { $match: { username } },
      {
        $project: {
          _id: 1,
          username: 1,
          last_updated: 1,
          cves: {
            $filter: {
              input: "$cves",
              as: "cve",
              cond: { 
                $and: [
                  { $gt: ["$$cve.updated_at", start] }, // Check if updated_at is greater than the timestamp
                  { $eq: ["$$cve.status", "ignored"] } // Check if status is 'resolved'
                ]
              } 
            }
          }
        }
      },
    ])
    .toArray();

  const watchlist_logs = await db
    .collection("watchlist_logs")
    .find({
      username, 
      timestamp: { 
        $gte: start
      }
    }).toArray();

  // Convert the response to the desired format
  const watchlistUpdates = watchlist_logs.filter(entry => entry.item.type === 'product')
    .map(entry => {
      const itemType = entry.item.type; // 'vendor' or 'product'
      const itemValue = entry.item.value; // 'RED HAT' or 'openSUSE'
      const action = entry.action; // 'ADD' or 'REMOVE'

      // Determine the status based on the action
      const status = action === 'ADD'
        ? "📌 Added to Watchlist"
        : "⛔️ Removed from Watchlist";

      // Create an object with the desired structure
      return {
        [itemType]: itemValue.charAt(0).toUpperCase() + itemValue.slice(1).toLowerCase(), // Capitalize the first letter and lowercase the rest
        status: status
      };
    });

  // Convert the resolved and ignored arrays to the desired format
  const actions = [
    ...resolved[0].cves.map(entry => ({
      type: "Resolved",
      cve: entry.cve_id,
      status: "✅ Fixed"
    })),
    ...ignored[0].cves.map(entry => ({
      type: "Ignored",
      cve: entry.cve_id,
      status: "⚠️ Low Risk"
    }))
  ];

  return {
    actions,
    watchlistUpdates,
  };
};

module.exports = {
  getTotalCVEs,
  getPatchableCVEs,
  getHighRiskCVEs,
  getNewCVEs,
  getWeeklyMonthlyData,
  getUpdateData,
  getResolvedYesterdayCVEs,
  getTodaysActivityData,
};
