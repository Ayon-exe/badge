

const getRecentCVEsCount = async (db, username, timeframe = "daily") => {
  const userWatchlist = await db.collection("watchlist").findOne({ username });

  if (!userWatchlist || !userWatchlist.watchlists.length) {
    return { username, recentCVECount: 0, graphData: [] };
  }

  const vendors = [];
  const products = [];
  userWatchlist.watchlists.forEach(watchlist => {
    watchlist.items.forEach(item => {
      if (item.vendor) vendors.push(item.vendor);
      if (item.product) products.push(item.product);
    });
  });

  if (vendors.length === 0 && products.length === 0) {
    return { username, recentCVECount: 0, graphData: [] };
  }

  let graphData = [];

  if (timeframe === "daily") {
    graphData = await getDailyCVEsForWatchlist(db, vendors, products);
  } else if (timeframe === "weekly") {
    graphData = await getWeeklyCVEsForWatchlist(db, vendors, products);
  } else if (timeframe === "monthly") {
    graphData = await getMonthlyCVEsForWatchlist(db, vendors, products);
  }

  const recentCVECount = graphData.reduce((acc, entry) => acc + entry.CVEs, 0);

  return { username, recentCVECount, graphData };
};

// Daily CVEs from One Month Ago (Sunday - Saturday)
const getDailyCVEsForWatchlist = async (db, vendors, products) => {
  const startDate = new Date();
  startDate.setMonth(startDate.getMonth() - 1); // Move back 1 month
  startDate.setDate(startDate.getDate() - startDate.getDay()); // Align to the last Sunday

  const dailyData = [];

  for (let i = 0; i < 7; i++) {
    const day = new Date(startDate);
    day.setDate(startDate.getDate() + i);

    const cveCount = await db.collection("unified_cves").countDocuments({
      $or: [{ "cpe.vendor": { $in: vendors } }, { "cpe.product": { $in: products } }],
      published_at: { $gte: day, $lt: new Date(day.getTime() + 86400000) }, // Next day range
    });

    dailyData.push({
      name: day.toLocaleString("default", { weekday: "long" }), // Sunday - Saturday
      CVEs: cveCount,
    });
  }

  return dailyData;
};

//  Weekly CVEs - Last 4 Weeks Starting From a Month Ago
const getWeeklyCVEsForWatchlist = async (db, vendors, products) => {
  const startDate = new Date();
  startDate.setMonth(startDate.getMonth() - 1); // Move back 1 month

  const weeklyData = [];

  for (let i = 3; i >= 0; i--) {
    const startOfWeek = new Date(startDate);
    startOfWeek.setDate(startDate.getDate() - (i * 7));
    startOfWeek.setHours(0, 0, 0, 0);

    const endOfWeek = new Date(startOfWeek);
    endOfWeek.setDate(startOfWeek.getDate() + 7);

    const cveCount = await db.collection("unified_cves").countDocuments({
      $or: [{ "cpe.vendor": { $in: vendors } }, { "cpe.product": { $in: products } }],
      published_at: { $gte: startOfWeek, $lt: endOfWeek },
    });

    weeklyData.push({
      name: `Week ${4 - i}`,
      CVEs: cveCount,
    });
  }

  return weeklyData;
};

// Monthly CVEs - Last 12 Months (Including Past Month)
const getMonthlyCVEsForWatchlist = async (db, vendors, products) => {
  const startDate = new Date();
  startDate.setMonth(startDate.getMonth() - 12); // Start from 12 months back

  const monthlyData = [];

  for (let i = 0; i < 12; i++) {
    const startOfMonth = new Date(startDate.getFullYear(), startDate.getMonth() + i, 1);
    const endOfMonth = new Date(startDate.getFullYear(), startDate.getMonth() + i + 1, 1);

    const cveCount = await db.collection("unified_cves").countDocuments({
      $or: [{ "cpe.vendor": { $in: vendors } }, { "cpe.product": { $in: products } }],
      published_at: { $gte: startOfMonth, $lt: endOfMonth },
    });

    monthlyData.push({
      name: startOfMonth.toLocaleString("default", { month: "short" }), // Jan - Dec
      CVEs: cveCount,
    });
  }

  return monthlyData;
};

const getUnpatchedFixableCVEs = async (db, username) => {
  const userWatchlist = await db.collection("watchlist").findOne({ username });
  if (!userWatchlist) return { message: "No watchlist found" };

  const vendors = [];
  const products = [];
  userWatchlist.watchlists.forEach(watchlist => {
    watchlist.items.forEach(item => {
      if (item.vendor) vendors.push(item.vendor);
      if (item.product) products.push(item.product);
    });
  });

  const result = await db.collection("unified_cves").aggregate([
    {
      $match: {
        $or: [{ "cpe.vendor": { $in: vendors } }, { "cpe.product": { $in: products } }],
        patch_url: { $exists: true, $ne: null },
      },
    },
    { $group: { _id: "$cvss_score", count: { $sum: 1 } } },
    { $sort: { _id: -1 } },
  ]).toArray();

  return {
    username,
    high: result.filter(cve => cve._id >= 7).reduce((acc, cve) => acc + cve.count, 0),
    medium: result.filter(cve => cve._id >= 4 && cve._id < 7).reduce((acc, cve) => acc + cve.count, 0),
    low: result.filter(cve => cve._id < 4).reduce((acc, cve) => acc + cve.count, 0),
  };
};

const getFixablePercentageOfCVEsWithPatchesAvailable = async (db, username) => {
  // Fetch user's watchlists
  const user = await db.collection("watchlist").findOne({ username });

  if (!user || !user.watchlists || user.watchlists.length === 0) {
    return { message: "No watchlists found", percentage: "0%" };
  }

  const vendors = [];
  const products = [];

  // Extract vendors and products from all watchlists
  user.watchlists.forEach(watchlist => {
    watchlist.items.forEach(item => {
      if (item.vendor) vendors.push(item.vendor);
      if (item.product) products.push(item.product);
    });
  });

  if (vendors.length === 0 && products.length === 0) {
    return { message: "No vendors or products found in watchlists", percentage: "0%" };
  }

  // ✅ Get **total CVEs** for watchlist vendors/products
  const totalCVEs = await db.collection("unified_cves").countDocuments({
    $or: [{ "cpe.vendor": { $in: vendors } }, { "cpe.product": { $in: products } }],
  });

  // ✅ Get **fixable CVEs** (CVEs that actually have patches available)
  const fixableCVEs = await db.collection("unified_cves").countDocuments({
    $or: [{ "cpe.vendor": { $in: vendors } }, { "cpe.product": { $in: products } }],
    patch_url: { $exists: true, $ne: null, $not: { $size: 0 } }, // Only count CVEs that have a valid patch
  });

  // ✅ Correctly calculate the **fixable percentage**
  const fixablePercentage = totalCVEs > 0 ? (fixableCVEs / totalCVEs) * 100 : 0;

  return {
    username,
    totalCVEs,
    fixableCVEs,
    percentage: `${fixablePercentage.toFixed(1)}%`,
    displayMessage: `${fixablePercentage.toFixed(0)}% of CVEs with patches available`,
  };
};

const getLiveExploitsForWatchlist = async (db, username) => {
  const userWatchlist = await db.collection("watchlist").findOne({ username });

  if (!userWatchlist || !userWatchlist.watchlists.length) {
    return { message: "No watchlists found" };
  }

  const vendors = [];
  const products = [];

  // Extract vendors and products from all watchlists
  userWatchlist.watchlists.forEach((watchlist) => {
    watchlist.items.forEach((item) => {
      if (item.vendor) vendors.push(item.vendor);
      if (item.product) products.push(item.product);
    });
  });

  if (vendors.length === 0 && products.length === 0) {
    return { message: "No vendors or products found in watchlists" };
  }

  // Fetch the top 10 CVEs with the highest CVSS scores and known exploits
  const liveExploits = await db.collection("unified_cves").aggregate([
    {
      $match: {
        $or: [{ "cpe.vendor": { $in: vendors } }, { "cpe.product": { $in: products } }],
        is_exploited: true, // Only include CVEs with known exploits
      },
    },
    {
      $addFields: {
        cvss_score: {
          $cond: {
            if: { $gt: [{ $ifNull: ["$cvss_metrics.cvss3.score", 0] }, 0] },
            then: "$cvss_metrics.cvss3.score",
            else: {
              $cond: {
                if: { $gt: [{ $ifNull: ["$cvss_metrics.cvss2.score", 0] }, 0] },
                then: "$cvss_metrics.cvss2.score",
                else: "$cvss_score",
              },
            },
          },
        },
      },
    },
    {
      $project: {
        _id: 0,
        cve_id: 1,
        affected_products: "$cpe.product",
        cvss_score: 1,
        last_updated: "$updated_at",
      },
    },
    { $sort: { cvss_score: -1, last_updated: -1 } }, // Sort by highest CVSS score, then latest update
    { $limit: 10 }, // Return only the top 10 results
  ]).toArray();

  return {
    username,
    total_exploits: liveExploits.length,
    liveExploits,
  };
};

const getFixableCVEsStats = async (db, username) => {
  const userWatchlist = await db.collection("watchlist").findOne({ username });

  if (!userWatchlist || !userWatchlist.watchlists || userWatchlist.watchlists.length === 0) {
    return {
      message: "User has no vendors in any watchlist",
      classification: "N/A",
    };
  }

  const vendors = [];

  userWatchlist.watchlists.forEach(watchlist => {
    watchlist.items.forEach(item => {
      if (item.vendor) vendors.push(item.vendor);
    });
  });

  if (vendors.length === 0) {
    return {
      message: "No vendors found in any watchlist",
      classification: "N/A",
    };
  }

  // Get total CVEs for watchlisted vendors
  const totalCVEs = await db.collection("unified_cves").countDocuments({
    "cpe.vendor": { $in: vendors }
  });

  if (totalCVEs === 0) {
    return {
      username,
      totalCVEs: 0,
      fixableCVEs: 0,
      fixablePercentage: "0%",
      avgFixDays: "N/A",
      classification: "N/A",
    };
  }

  // Get fixable CVEs (Only checking for patch_url, removing patch_release_date condition)
  const fixableCVEs = await db.collection("unified_cves").find(
    {
      "cpe.vendor": { $in: vendors },
      patch_url: { $ne: [], $ne: null }
    },
    { projection: { _id: 0, published_at: 1 } }
  ).toArray();

  if (fixableCVEs.length === 0) {
    return {
      username,
      totalCVEs,
      fixableCVEs: 0,
      fixablePercentage: "0%",
      avgFixDays: "N/A",
      classification: "N/A",
    };
  }

  // Calculate average days since the patch was released
  const currentDate = new Date();
  const totalDays = fixableCVEs.reduce((sum, cve) => {
    if (!cve.patch_release_date) return sum; // Ignore CVEs without patch_release_date
    const patchDate = new Date(cve.patch_release_date);
    return sum + Math.floor((currentDate - patchDate) / (1000 * 60 * 60 * 24));
  }, 0);

  // const avgFixDays = fixableCVEs.length > 0 ? (totalDays / fixableCVEs.length).toFixed(1) : "N/A";
  // console.log("fixableCVEs", fixableCVEs);
  const avgFixDays = fixableCVEs.length > 0 ? (totalDays / fixableCVEs.length).toFixed(1) : "N/A";
  const fixablePercentage = (fixableCVEs.length / totalCVEs) * 100;
  const fixablePercentageDisplay = fixablePercentage > 0 ? fixablePercentage.toFixed(1) : 0;

  // Risk Classification based on fixable percentage
  let classification = "N/A";
  if (fixablePercentage <= 10) classification = "Very Good (0-10%)";
  else if (fixablePercentage <= 25) classification = "Good (10-25%)";
  else if (fixablePercentage <= 40) classification = "Pay Attention (25-40%)";
  else if (fixablePercentage <= 60) classification = "Urgent (40-60%)";
  else classification = "Critical (60-100%)";

  return {
    username,
    totalCVEs,
    fixableCVEs: fixableCVEs.length,
    fixablePercentage: fixablePercentageDisplay,
    avgFixDays,
    classification,
  };
};

const getVendorsAndProductsFromWatchlist = async (db, username) => {
  const userWatchlist = await db.collection("watchlist").findOne(
    { username },
    { projection: { watchlists: 1, _id: 0 } } // Only retrieve "watchlists" field
  );

  if (!userWatchlist || !userWatchlist.watchlists.length) {
    return { message: "No vendors or products found in any watchlist", vendors: [], products: [] };
  }

  const vendors = new Set(); // Using a Set to avoid duplicates
  const products = new Set(); // Using a Set to avoid duplicates

  // Extract vendors and products from multiple watchlists
  userWatchlist.watchlists.forEach(watchlist => {
    watchlist.items.forEach(item => {
      if (item.vendor) vendors.add(item.vendor);
      if (item.product) products.add(item.product);
    });
  });

  // Return only username, vendors, and products arrays
  return { username, vendors: Array.from(vendors), products: Array.from(products) };
};

// get yearly count of cves 
const getCurrentCVEs = async (db, identifier) => {
  if (!db) throw new Error("Database instance is undefined.");

  const collection = db.collection("unified_cves");

  const currentDate = new Date();
  const startDate = new Date(currentDate.getFullYear(), currentDate.getMonth() - 11, 1); // Start of the month 12 months ago
  const endDate = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 1); // Start of the next month

  // Debugging: Log the date range
  // console.log("DEBUG: Calculating CVEs for the last 12 months");
  // console.log("DEBUG: Start Date:", startDate.toISOString());
  // console.log("DEBUG: End Date:", endDate.toISOString());

  // Ensure the filter includes only the last 12 months and matches the correct year
  const filter = {
    $or: [
      { "cpe.vendor": { $regex: new RegExp(`^${identifier}$`, "i") } },
      { "cpe.product": { $regex: new RegExp(`^${identifier}$`, "i") } },
    ],
    published_at: {
      $gte: startDate, // Start date is 12 months ago
      $lt: endDate, // End date is the start of the next month
    },
  };

  // Debugging: Log the filter being used
  // console.log("DEBUG: Filter for CVE count:", JSON.stringify(filter, null, 2));

  const currentCVEs = await collection.countDocuments(filter);

  // Debugging: Log the result
  // console.log(`DEBUG: Total CVEs for identifier "${identifier}":`, currentCVEs);

  return { identifier, currentCVEs };
};


const getMonthlyDistribution = async (db, identifier) => {
  if (!db) throw new Error("Database instance is undefined.");

  const collection = db.collection("unified_cves");
  const currentDate = new Date();
  const startDate = new Date(currentDate);
  startDate.setFullYear(startDate.getFullYear(), startDate.getFullMonth - 11,  - 1);

  const monthsArray = [];
  for (let i = 11; i >= 0; i--) {
    const date = new Date(
      currentDate.getFullYear(), currentDate.getMonth() - i, 1
    );

    monthsArray.push({
      year: date.getFullYear(),
      month: date.getMonth() + 1,
      name: date.toLocaleString("default", { month: "short" }),
      count: 0,
    });
  }

  // Update filter to include both vendors and products
  const filter = {
    $or: [
      { "cpe.vendor": { $regex: new RegExp(`^${identifier}$`, "i") } },
      { "cpe.product": { $regex: new RegExp(`^${identifier}$`, "i") } },
    ],
    published_at: { $gte: startDate, 
      $lt: new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 1)
    }
  };

  // Aggregate raw data for the filtered documents
  const rawData = await collection.aggregate([
    { $match: filter },
    { $group: 
      { _id: {   
        year: { $year: "$published_at" },
        month: { $month: "$published_at" }
      }, 
        count: { $sum: 1 } 
      } 
    }
  ]).toArray();

  // Assign the count values to the respective months
  rawData.forEach(({ _id, count }) => {
    const match = monthsArray.find(
      (m) => m.year === _id.year && m.month === _id.month && m.year === _id.year
    );
    if (match) {
      // If it's the current month, only count data up to today
      if (
        _id.year === currentDate.getFullYear() &&
        _id.month === currentDate.getMonth() + 1
      ) {
        const today = new Date(currentDate);
        today.setHours(0, 0, 0, 0);
        const currentMonthData = collection.countDocuments({
          ...filter,
          published_at: {
            $gte: new Date(currentDate.getFullYear(), currentDate.getMonth(), 1),
            $lt: today,
          },
        });
        match.count = currentMonthData;
      } else {
        match.count = count;
      }
    }
  });

  // Debug log for months count data
  // console.log("DEBUG: Monthly Distribution Data:", monthsArray);

  return {
    identifier,
    monthlyDistribution: monthsArray.map((m) => ({
      name: m.name,
      count: m.count,
    })),
  };
};

const getAvgMonthlyCVEs = async (db, identifier) => {
  if (!db) throw new Error("Database instance is undefined.");

  const collection = db.collection("unified_cves");
  const currentDate = new Date();
  const startDate = new Date(currentDate);
  startDate.setFullYear(startDate.getFullYear() - 1);

  // Modify the filter to match both vendor and product
  const filter = { 
    $or: [
      { "cpe.vendor": { $regex: new RegExp(`^${identifier}$`, "i") } },
      { "cpe.product": { $regex: new RegExp(`^${identifier}$`, "i") } }
    ],
    published_at: { $gte: startDate, $lt: currentDate }
  };

  // Aggregate the data to get the average number of CVEs per month
  const result = await collection
    .aggregate([
      { $match: filter },
      { $group: { _id: { $month: "$published_at" }, count: { $sum: 1 } } },
      { $group: { _id: null, avgMonthlyCV: { $avg: "$count" } } }
    ])
    .toArray();

  return {
    identifier,
    avgMonthlyCV: result.length > 0 ? result[0].avgMonthlyCV : 0
  };
};

const getAvgWeeklyCVEs = async (db, identifier) => {
  if (!db) throw new Error("Database instance is undefined.");

  const collection = db.collection("unified_cves");
  const currentDate = new Date();
  const startDate = new Date(currentDate);
  startDate.setFullYear(startDate.getFullYear() - 1);

  // Modify the filter to match both vendor and product
  const filter = { 
    $or: [
      { "cpe.vendor": { $regex: new RegExp(`^${identifier}$`, "i") } },
      { "cpe.product": { $regex: new RegExp(`^${identifier}$`, "i") } }
    ],
    published_at: { $gte: startDate, $lt: currentDate }
  };

  // Aggregate the data to get the weekly count of CVEs
  const result = await collection
    .aggregate([
      { $match: filter },
      { $group: { _id: { $isoWeek: "$published_at" }, count: { $sum: 1 } } },
      { $group: { _id: null, avgWeeklyCV: { $avg: "$count" } } }
    ])
    .toArray();

  return { identifier, avgWeeklyCV: result.length > 0 ? result[0].avgWeeklyCV : 0 };
};

const getMonthlyChangeStats = async (db, identifier) => {
  if (!db) throw new Error("Database instance is undefined.");

  const collection = db.collection("unified_cves");
  const currentDate = new Date();

  // Define time periods
  const currentMonth = currentDate.getMonth();
  const currentYear = currentDate.getFullYear();


    // Calculate the time periods for last month and two months prior
  const lastMonthStart = new Date(currentYear, currentMonth - 1, 1); // Start of 1 month prior
  const lastMonthEnd = new Date(currentYear, currentMonth, 1); // Start of the current month
  const prevMonthStart = new Date(currentYear, currentMonth - 2, 1); // Start of 2 months prior
  const prevMonthEnd = new Date(currentYear, currentMonth - 1, 1); // Start of 1 month prior

  // Calculate the same month last year for 1 month prior
  const lastYearSameMonthStart = new Date(currentYear - 1, currentMonth - 1, 1); // Start of 1 month prior last year
  const lastYearSameMonthEnd = new Date(currentYear - 1, currentMonth, 1); // Start of the current month last year

  // Update filter to include both vendors and products in the nested `cpe` array
  const filter = {
    $or: [
      { "cpe.vendor": { $regex: new RegExp(`^${identifier}$`, "i") } },
      { cpe: { $elemMatch: { product: { $regex: new RegExp(`^${identifier}$`, "i") } } } }
    ]
  };


  // Fetch CVE counts for the required months
  const lastMonthCount = await collection.countDocuments({ 
    ...filter, 
    published_at: { $gte: lastMonthStart, $lt: lastMonthEnd }
  });

  const prevMonthCount = await collection.countDocuments({ 
    ...filter, 
    published_at: { $gte: prevMonthStart, $lt: prevMonthEnd }
  });

  const lastYearSameMonthCount = await collection.countDocuments({ 
    ...filter, 
    published_at: { $gte: lastYearSameMonthStart, $lt: lastYearSameMonthEnd }
  });

  // Calculate percentage change
  const percentLastMonthChange = prevMonthCount === 0 ? 
    (lastMonthCount > 0 ? 100 : 0) : 
    ((lastMonthCount - prevMonthCount) / prevMonthCount) * 100;

  const percentLastYearSameMonthChange = lastYearSameMonthCount === 0 ? 
    (lastMonthCount > 0 ? 100 : 0) : 
    ((lastMonthCount - lastYearSameMonthCount) / lastYearSameMonthCount) * 100;

  return {
    changeLastMonth: percentLastMonthChange.toFixed(2) + "%",
    changeLastYear: percentLastYearSameMonthChange.toFixed(2) + "%"
  };
};

const getVendorDataFromWatchlist = async (db, username) => {
  if (!db) throw new Error("Database instance is undefined.");

  const userWatchlist = await db.collection("watchlist").findOne(
    { username },
    { projection: { watchlists: 1, _id: 0 } }
  );

  if (!userWatchlist || !userWatchlist.watchlists.length) {
    return { message: "No identifiers found in any watchlist", identifiers: [] };
  }

  const identifiers = new Set();
  userWatchlist.watchlists.forEach(watchlist => {
    watchlist.items.forEach(item => {
      if (item.vendor) identifiers.add(item.vendor.trim().toLowerCase());
      if (item.product) identifiers.add(item.product.trim().toLowerCase());
    });
  });

  if (identifiers.size === 0) {
    return { message: "No identifiers found in watchlist", identifiers: [] };
  }

  const identifierData = await Promise.all(Array.from(identifiers).map(async (identifier) => {
    return {
      "name":identifier,
      ...(await getCurrentCVEs(db, identifier)),
      ...(await getAvgMonthlyCVEs(db, identifier)),
      ...(await getAvgWeeklyCVEs(db, identifier)),
      // ...(await getPercentageChangeLastMonth(db, identifier)),
      // ...(await getPercentageChangeLastYearMonth(db, identifier)),
      ...(await getMonthlyChangeStats(db,identifier)),
      ...(await getMonthlyDistribution(db, identifier))
    };
  }));

  return { username, vendors: identifierData };
};

const getTotalVendors = async (db, username) => {
  try {
    // console.log("DEBUG: Function called with username:", username);
    
    const userWatchlist = await db.collection("watchlist").findOne({ username });
    // console.log("DEBUG: User watchlist found:", userWatchlist ? "Yes" : "No");
    
    if (!userWatchlist) {
      // console.log("DEBUG: No watchlist document found for user");
      return 0;
    }
    
    if (!userWatchlist.watchlists) {
      // console.log("DEBUG: Watchlist document exists but has no watchlists array");
      return 0;
    }
    
    // console.log(`DEBUG: Found ${userWatchlist.watchlists.length} watchlists for user`);
  
    const uniqueVendors = new Set();
    
   
    userWatchlist.watchlists.forEach((watchlist, index) => {
      // console.log(`DEBUG: Examining watchlist #${index+1}: "${watchlist.name}"`);
      
      if (!watchlist.items || !Array.isArray(watchlist.items)) {
        // console.log(`DEBUG: Watchlist #${index+1} has no items array`);
        return; 
      }
      
      // console.log(`DEBUG: Watchlist #${index+1} has ${watchlist.items.length} items`);
      
     
      watchlist.items.forEach((item, itemIndex) => {
        // console.log(`DEBUG: Item #${itemIndex+1}:`, JSON.stringify(item));
        
        if (item.vendor) {
          // console.log(`DEBUG: Found vendor: "${item.vendor}"`);
          uniqueVendors.add(item.vendor.toLowerCase());
        } else {
          // console.log(`DEBUG: Item has no vendor property`);
        }
      });
    });
    
    
    // console.log("DEBUG: Unique vendors found:", Array.from(uniqueVendors));
    // console.log("DEBUG: Total unique vendors:", uniqueVendors.size);
    
    return uniqueVendors.size;
    
  } catch (error) {
    // console.error("DEBUG: Error getting total vendors:", error);
    return 0;
  }
};

const getTotalProducts = async (db, username) => {
  try {
    // console.log("DEBUG: Function called with username:", username);
    

    const userWatchlist = await db.collection("watchlist").findOne({ username });
    // console.log("DEBUG: User watchlist found:", userWatchlist ? "Yes" : "No");
    
    if (!userWatchlist) {
      // console.log("DEBUG: No watchlist document found for user");
      return 0;
    }
    
    if (!userWatchlist.watchlists) {
      // console.log("DEBUG: Watchlist document exists but has no watchlists array");
      return 0;
    }
    
    // console.log(`DEBUG: Found ${userWatchlist.watchlists.length} watchlists for user`);
    
   
    const uniqueProducts = new Set();
   
    userWatchlist.watchlists.forEach((watchlist, index) => {
      // console.log(`DEBUG: Examining watchlist #${index+1}: "${watchlist.name}"`);
      
      if (!watchlist.items || !Array.isArray(watchlist.items)) {
        // console.log(`DEBUG: Watchlist #${index+1} has no items array`);
        return; 
      }
      
      // console.log(`DEBUG: Watchlist #${index+1} has ${watchlist.items.length} items`);
      
     
      watchlist.items.forEach((item, itemIndex) => {
        // console.log(`DEBUG: Item #${itemIndex+1}:`, JSON.stringify(item));
        
        if (item.product) {
          // console.log(`DEBUG: Found product: "${item.product}"`);
          uniqueProducts.add(item.product.toLowerCase());
        } else {
          // console.log(`DEBUG: Item has no product property`);
        }
      });
    });
    
    
    // console.log("DEBUG: Unique products found:", Array.from(uniqueProducts));
    // console.log("DEBUG: Total unique products:", uniqueProducts.size);
    
    return uniqueProducts.size;
    
  } catch (error) {
    // console.error("DEBUG: Error getting total products:", error);
    return 0;
  }
};

const getTotalOpenCVEs = async (db, username) => {
  try {
  
    const userResolutionStatus = await db.collection("resolution_status").findOne({ username });
  
    if (!userResolutionStatus || !userResolutionStatus.cves) return 0;

    const openCVEsCount = userResolutionStatus.cves.filter(cve => cve.status === "open").length;
    
    return openCVEsCount;
  } catch (error) {
    // console.error("Error getting total open CVEs:", error);
    return 0;
  }
};

const getTotalResolvedCVEs = async (db, username) => {
  try {
    
    const userResolutionStatus = await db.collection("resolution_status").findOne({ username });
    
  
    if (!userResolutionStatus || !userResolutionStatus.cves) return 0;
    
   
    const resolvedCVEsCount = userResolutionStatus.cves.filter(cve => cve.status === "resolved").length;
    
    return resolvedCVEsCount;
  } catch (error) {
    // console.error("Error getting total resolved CVEs:", error);
    return 0;
  }
};

const getTotalIgnoredCVEs = async (db, username) => {
  try {
   
    const userResolutionStatus = await db.collection("resolution_status").findOne({ username });
    
   
    if (!userResolutionStatus || !userResolutionStatus.cves) return 0;
    
    const ignoredCVEsCount = userResolutionStatus.cves.filter(cve => cve.status === "ignored").length;
    
    return ignoredCVEsCount;
  } catch (error) {
    // console.error("Error getting total ignored CVEs:", error);
    return 0;
  }
};

const getVendorsAndProductsTotalCVECount = async (db, username) => {
  if (!db) throw new Error("Database instance is undefined.");

  // Fetch user's watchlist
  const userWatchlist = await db.collection("watchlist").findOne(
    { username },
    { projection: { watchlists: 1, _id: 0 } }
  );

  if (!userWatchlist || !userWatchlist.watchlists.length) {
    return { message: "No vendors or products found in any watchlist", vendors: [], products: [] };
  }

  // Extract vendors and products (case-insensitive)
  const vendors = new Set();
  const products = new Set();
  userWatchlist.watchlists.forEach(watchlist => {
    watchlist.items.forEach(item => {
      if (item.vendor) vendors.add(item.vendor.trim().toLowerCase()); // Normalize case & trim spaces
      if (item.product) products.add(item.product.trim().toLowerCase()); // Normalize case & trim spaces
    });
  });

  if (vendors.size === 0 && products.size === 0) {
    return { message: "No vendors or products found in watchlist", vendors: [], products: [] };
  }

  // Fetch data for both vendors and products in parallel
  const vendorDataPromises = Array.from(vendors).map(async (vendor) => {
    const [
      currentCVEs,
    ] = await Promise.all([
      getCurrentCVEs(db, vendor),
    ]);

    return {
      name: vendor,  // Matches frontend field "name"
      CVEs: currentCVEs?.currentCVEs ?? 0,
    };
  });

  const productDataPromises = Array.from(products).map(async (product) => {
    const [
      currentCVEs,
    ] = await Promise.all([
      getCurrentCVEs(db, product),
    ]);

    return {
      name: product,  // Matches frontend field "name"
      CVEs: currentCVEs?.currentCVEs ?? 0,
    };
  });

  // Wait for all vendor and product data to resolve
  const vendorData = await Promise.all(vendorDataPromises);
  const productData = await Promise.all(productDataPromises);

  return { username, vendors: vendorData, products: productData };
};


module.exports = {
  getRecentCVEsCount,
  getDailyCVEsForWatchlist,
  getWeeklyCVEsForWatchlist,
  getMonthlyCVEsForWatchlist,
  getUnpatchedFixableCVEs,
  getFixablePercentageOfCVEsWithPatchesAvailable,
  getFixableCVEsStats,
  getLiveExploitsForWatchlist,
  getVendorsAndProductsFromWatchlist,
  getVendorDataFromWatchlist,
  getTotalVendors,
  getTotalProducts,
  getTotalOpenCVEs,
  getTotalResolvedCVEs,
  getTotalIgnoredCVEs,
  getVendorsAndProductsTotalCVECount,
  
};