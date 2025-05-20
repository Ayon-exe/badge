const { 
  createBoxDataModel,
  createUnifiedModel,
  createCVEModel,
  createCweDataModel,
  createCvssDataModel, 
  createExploitedDataModel, 
  createFixesDataModel,
  createTopVendorsDataModel, 
  createCveStatsDataModel,
} = require("../models/CVE");
const logger = require("../logger");
const semver = require("semver");



const getUniqueVendors = async (db) => {
  const searchData = await db
    .collection("search")
    .findOne({ _id: "search_data" });

  if (searchData) {
    logger.info("using searchData");
    const vendors = searchData.vendors;
    logger.info("done with unique part");
    // console.log(Array.from(vendors));
    return Array.from(vendors);
  }
  logger.info("No data found in the 'SEARCH' collection");

  const cveCollection = createCVEModel(db);
  const cveRecords = await cveCollection.find({}).toArray();

  const vendors = new Set();

  cveRecords.forEach((record) => {
    if (record.cpe_data) {
      record.cpe_data.forEach((affected) => {
        if (affected.vendor) {
          //vendors.add(affected.vendor.toLowerCase()); // Normalize to lowercase
          vendors.add(affected.vendor.toLowerCase());
        }
      });
    }
  });
  // console.log(Array.from(vendors));

  //console.log("Unique vendors:" + Array.from(vendors)) ;
  return Array.from(vendors);
};

// Function to check if the given vendor exists in the CVE records
const vendorExistsInCVE = async (db, vendorName) => {
  const uniqueVendors = await getUniqueVendors(db);
  return uniqueVendors.some((vendor) => vendor.includes(vendorName));
};

const getUniqueProducts = async (db) => {
  const searchData = await db
    .collection("search")
    .findOne({ _id: "search_data" });

  if (searchData) {
    logger.info("using searchData");
    const products = searchData.products;
    // console.log(Array.from(products));
    return Array.from(products);
  }
  logger.info("No data found in the 'SEARCH' collection");
  const cveCollection = createCVEModel(db);
  const cveRecords = await cveCollection.find({}).toArray();

  const products = new Set();

  cveRecords.forEach((record) => {
    if (record.cpe_data) {
      record.cpe_data.forEach((affected) => {
        if (affected.product) {
          //products.add(affected.product.toLowerCase()); // Normalize to lowercase
          products.add(affected.product.toLowerCase());
        }
      });
    }
  });

  //console.log("Unique products:" + Array.from(products)) ;
  return Array.from(products);
};

// Function to check if the given product exists in the CVE records
const productExistsInCVE = async (db, productName) => {
  const uniqueProducts = await getUniqueProducts(db);
  return uniqueProducts.some((product) => product.includes(productName));
};

// Example of a route handler that uses this function
const checkVendor = async (db, vendorName) => {
  const exists = await vendorExistsInCVE(db, vendorName);
  return exists;
};
const filterByCVEId = async (db, cveId) => {
  const unifiedCollection = createUnifiedModel(db);
  return await unifiedCollection.findOne({ cve_id: cveId });
};

const getCveStatisticsByVendor = async (db, vendor) => {
  const unifiedCollection = createUnifiedModel(db);

  // Normalize vendor name for searching
  const normalizedVendor = vendor.replace(/\s+/g, "").toLowerCase();

  const cweTypeMapping = {
    "CWE-120": "Overflow",
    "CWE-787": "Memory Corruption",
    "CWE-89": "SQL Injection",
    "CWE-79": "XSS",
    "CWE-22": "Directory Traversal",
    "CWE-98": "File Inclusion",
    "CWE-352": "CSRF",
    "CWE-611": "XXE",
    "CWE-918": "SSRF",
    "CWE-601": "Open Redirect",
    "CWE-20": "Input Validation",
  };

  // Aggregation to get CVE statistics
  const statistics = await unifiedCollection
    .aggregate([
      {
        $match: {
          "cpe.vendor": { $regex: normalizedVendor, $options: "i" }, // Match the vendor case-insensitively
        },
      },
      {
        $unwind: "$weaknesses", // Unwind the weaknesses array to access individual CWE IDs
      },
      {
        $match: {
          "weaknesses.cwe_id": { $in: Object.keys(cweTypeMapping) }, // Filter for known CWE IDs
        },
      },
      {
        // Group by CVE ID to ensure we only count distinct CVEs
        $group: {
          _id: {
            year: { $year: "$published_at" }, // Group by the year of publication
            cweId: "$weaknesses.cwe_id", // Group by CWE ID
            cveId: "$cve_id", // Group by CVE ID to ensure distinct counting
          },
        },
      },
      {
        // Now group by year and CWE ID to count distinct CVEs
        $group: {
          _id: { year: "$_id.year", cweId: "$_id.cweId" }, // Group by year and CWE ID
          count: { $sum: 1 }, // Count distinct CVEs for each CWE ID
        },
      },
      {
        // Group the results by year to compile the vulnerabilities
        $group: {
          _id: "$_id.year",
          vulnerabilities: {
            $push: {
              type: {
                $cond: {
                  if: { $in: ["$_id.cweId", Object.keys(cweTypeMapping)] },
                  then: {
                    $arrayElemAt: [
                      Object.keys(cweTypeMapping),
                      {
                        $indexOfArray: [
                          Object.keys(cweTypeMapping),
                          "$_id.cweId",
                        ],
                      },
                    ],
                  },
                  else: "Other", // In case it doesn't match any predefined type
                },
              },
              count: "$count",
            },
          },
        },
      },
      {
        // Restructure the output to show vulnerabilities in key-value format
        $project: {
          _id: 1,
          vulnerabilities: {
            $arrayToObject: {
              $map: {
                input: "$vulnerabilities",
                as: "vuln",
                in: {
                  k: "$$vuln.type",
                  v: "$$vuln.count",
                },
              },
            },
          },
        },
      },
      { $sort: { _id: -1 } }, // Sort by year descending
    ])
    .toArray();

  return statistics;
};
const processCVEStats = async (db) => {
  // today
  const now = new Date();

  // yesterday
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);

  // 7 days back
  const sevenDaysBack = new Date(now);
  sevenDaysBack.setDate(now.getDate() - 7);
  // month back
  const monthBack = new Date(now);
  monthBack.setMonth(now.getMonth() - 1);

  // console.log(yesterday, sevenDaysBack, monthBack);

  const newAndUpdatedCVEs = {
    createdSinceYesterday: await getCVECount(db, {
      published_at: { $gte: yesterday },
    }),
    updatedSinceYesterday: await getCVECount(db, {
      updated_at: { $gte: yesterday },
    }),
    createdLast7Days: await getCVECount(db, {
      published_at: { $gte: sevenDaysBack },
    }),
    updatedLast7Days: await getCVECount(db, {
      updated_at: { $gte: sevenDaysBack },
    }),
    createdLast30Days: await getCVECount(db, {
      published_at: { $gte: monthBack },
    }),
    updatedLast30Days: await getCVECount(db, {
      updated_at: { $gte: monthBack },
    }),
  };

  const exploitedStats = await getExploitedVulnerabilitiesStats(db);

  return {
    newAndUpdatedCVEs,
    exploitedStats,
  };
};

const updateCVEStats = async (db) => {
  const cveStatsDataCollection = createCveStatsDataModel(db);

  logger.info("udpating radial Graph-rightMost data");
  const result = await processCVEStats(db);

  const status = await cveStatsDataCollection.updateOne(
    {_id: "home"},
    {$set: {data: result, updated_at: new Date() } },
    { upsert: true }
  );
  const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
  logger.info(msg);
}

const getCVEStats =  async (db) => {
  const cveStatsDataCollection = createCveStatsDataModel(db);
  const result = await cveStatsDataCollection.findOne({_id: "home"});
  // if data exist for Home page
  if ( result ){
    logger.info("returning Cached CVE Stats Data for Home radial Graph");
    return result.data;
  }

  // process if cached not found
  logger.info("processing CVE Stats Data");
  return await processCVEStats(db);
}

//attack vector
const getAttackVectorStats = async (db, vendor) => {
  const unifiedCollection = createCVEModel(db);
  const match = {};
  if (vendor !== undefined && vendor !== null) {
    match["cpe_data.vendor"] = new RegExp(vendor, "i");
  } else {
    match["cpe_data.vendor"] = "";
  }

  const attackVectors = await unifiedCollection
    .aggregate([
      {
        $match: match,
      },
      {
        $unwind: "$cvss_data",
      },
      {
        $group: {
          _id: "$cvss_data.attackVector",
          count: { $sum: 1 },
        },
      },
      {
        $project: {
          _id: 0,
          attackVector: "$_id",
          count: 1,
        },
      },
    ])
    .toArray();

  return attackVectors;
};

// calculate CWE stats
const processCWEStats = async (db, vendor) => {
  const unifiedCollection = createUnifiedModel(db);
  const match = {
    published_at: {
      $gte: new Date("2014-01-01T00:00:00Z"),
      $lt: new Date(),
    },
  };

  if (vendor !== undefined && vendor !== null) {
    match["cpe.vendor"] = new RegExp(vendor, "i");
  }

  const VulnerabilityGraphData = await unifiedCollection
    .aggregate([
      {
        $match: match,
      },
      {
        $unwind: "$weaknesses",
      },
      {
        $group: {
          _id: {
            year: { $year: "$published_at" },
            cwe_id: "$weaknesses.cwe_id",
          },
          count: { $sum: 1 },
        },
      },
      {
        $group: {
          _id: "$_id.year",
          Total: { $sum: "$count" },
          weaknesses: {
            $push: {
              k: "$_id.cwe_id",
              v: "$count",
            },
          },
        },
      },
      {
        $project: {
          date: { $toString: "$_id" },
          Total: 1,
          weaknesses: { $arrayToObject: "$weaknesses" },
        },
      },
      {
        $replaceRoot: {
          newRoot: {
            date: "$date",
            Total: "$Total",
            Overflow: { $ifNull: ["$weaknesses.CWE-120", 0] },
            "Memory Corruption": { $ifNull: ["$weaknesses.CWE-119", 0] },
            "SQL Injection": { $ifNull: ["$weaknesses.CWE-89", 0] },
            XSS: { $ifNull: ["$weaknesses.CWE-79", 0] },
            "Directory Traversal": { $ifNull: ["$weaknesses.CWE-22", 0] },
            "File Inclusion": { $ifNull: ["$weaknesses.CWE-98", 0] },
            CSRF: { $ifNull: ["$weaknesses.CWE-352", 0] },
            XXE: { $ifNull: ["$weaknesses.CWE-611", 0] },
            SSRF: { $ifNull: ["$weaknesses.CWE-918", 0] },
          },
        },
      },
      {
        $sort: { date: 1 },
      },
    ])
    .toArray();
  return VulnerabilityGraphData;
};

// update CWE stats
const updateCWEStats = async (db, vendor) => {
  const cweDataCollection = createCweDataModel(db);

  logger.info("udpating Line Graph data");
  const result = await processCWEStats(db, vendor);

  if ( vendor === null || vendor === undefined ){
    const status = await cweDataCollection.updateOne(
      {_id: "home"},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
  } else {
    const status = await cweDataCollection.updateOne(
      {_id: vendor},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
  }
}
    
// get CWE stats
const getCWEStats = async (db, vendor) => {
  const cweDataCollection = createCweDataModel(db);
  // vendor check
  if ( vendor === undefined || vendor === null ){
    // console.log("checking cached collection ");
    const result = await cweDataCollection.findOne({_id: "home"});
    // if data exist for Home page
    if ( result ){
      logger.info("returning Cached CWE Data for Home line Graph");
      return result.data;
    }
  } else {
    const result = await cweDataCollection.findOne({_id: vendor});
    // if data exist for a vendor
    if ( result ){
      const msg = `returning Cached CWE Data for ${vendor}`;
      logger.info(msg);
      return result.data;
    }
  }

  // process if cached not found
  logger.info("processing CWE Data");
  const result = await processCWEStats(db, vendor);
  // console.log(result);

  return result
}

// Function to count CVEs based on given criteria
const getCVECount = async (db, criteria) => {
  return await db.collection("unified_cves").countDocuments(criteria);
};

const getEpssScoreChangePercentage = async (db, vendor) => {
  let query = {};
  if (vendor) {
    query["cpe.vendor"] = {
      $regex: new RegExp(vendor, "i"),
    };
  } else {
    const currentDate = new Date();
    const lastYear = new Date(
      currentDate.getFullYear() - 1,
      currentDate.getMonth(),
      currentDate.getDate()
    );
    query["published_at"] = {
      $gte: lastYear,
      $lt: currentDate,
    };
  }
  // Fetch only the epss scores for the specified vendor
  const result = await db
    .collection("unified_cves")
    .aggregate([
      {
        $match: query, // Filter by vendor
      },
      {
        $group: {
          _id: null, // Grouping by null to get a single result
          initialEpss: { $min: "$epss.epss_score" }, // Get the minimum EPS score
          finalEpss: { $max: "$epss.epss_score" }, // Get the maximum EPS score
        },
      },
      {
        $project: {
          _id: 0, // Exclude the _id field from the result
          changePercentage: {
            $divide: [
              { $subtract: ["$finalEpss", "$initialEpss"] },
              "$initialEpss",
            ],
          },
        },
      },
    ])
    .toArray();
  // console.log(result);

  const change_percentage = result[0];
  // console.log("result result)

  return change_percentage;
};

const getVendorCount = async (db) => {
  const count = await db
    .collection("search")
    .aggregate([
      { $match: { _id: "search_data" } },
      { $project: { totalVendors: { $size: "$vendors" } } },
    ])
    .toArray();

  return count[0].totalVendors;
};

const getExploitedCVEs = async (db, vendor) => {
  let query = {};
  query.is_exploited = true;
  if (vendor !== null && vendor !== "") {
    query["cpe.vendor"] = {
      $regex: new RegExp(vendor, "i"),
    };
  }
  // console.log(query);
  const exploited_count = await db
    .collection("unified_cves")
    .countDocuments(query);

  return exploited_count;
};

const getBoxDataStats = async (db, vendor) => {
  const boxDataCollection = createBoxDataModel(db);
  // vendor check
  if ( vendor === undefined || vendor === null ){

    // console.log("checking cached collection ");
    const result = await boxDataCollection.findOne({_id: "home"});
    // if data exist for Home page
    if ( result ){
      logger.info("returning Cached Boxdata for Home BoxData");
      return result.data;
    }
  } else {
    const result = await boxDataCollection.findOne({_id: vendor});
    // if data exist for a vendor
    if ( result ){
      const msg = `returning Cached Boxdata for ${vendor}`;
      logger.info(msg);
      return result.data;
    }
  }

  // process if cached not found
  logger.info("processing Boxdata");
  const result = await processBoxDataStats(db, vendor);
  // console.log(result);

  return result
};

const processBoxDataStats = async (db, vendor) => {
  const currentDate = new Date();
  const lastMonth = new Date(
    currentDate.getFullYear(),
    currentDate.getMonth(),
    1
  );
  // console.log("last month", lastMonth);
  const lastYear = new Date(currentDate.getFullYear(), 0, 0);

  let match = {};
  if (vendor) {
    match["cpe.vendor"] = { $regex: new RegExp(vendor, "i") };
  }

  const total_vuln = await db.collection("unified_cves")
    .countDocuments(match);

  match.published_at = {
    $gt: lastYear,
    $lt: currentDate,
  };

  const vuln_this_year = await db
    .collection("unified_cves")
    .countDocuments(match);
  // const changed_epss = await getEpssScoreChangePercentage(db, vendor);
  const vuln_exploited = await getExploitedCVEs(db, vendor);

  match.published_at = {
    $gt: lastMonth,
  };
  // console.log(match);
  const vuln_this_month = await db
    .collection("unified_cves")
    .countDocuments(match);

  const cvss_info = await getCvssScoreRanges(db, vendor);
  const weighted_avg = cvss_info.weightedAverage;

  //console.log(changed_epss);

  // const vendors_count = await getVendorCount(db);

  return {
    vuln_this_year,
    // change_in_epss: changed_epss.changePercentage.toFixed(1),
    total_vuln,
    vuln_exploited,
    vuln_this_month,
    weighted_avg,
  };
};

const updateBoxDataStats = async (db, vendor) => {
  const boxDataCollection = createBoxDataModel(db);

  logger.info("udpating Box data");
  const result = await processBoxDataStats(db, vendor);

  if ( vendor === null || vendor === undefined ){
    const status = await boxDataCollection.updateOne(
      {_id: "home"},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
  } else {
    const status = await boxDataCollection.updateOne(
      {_id: vendor},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
  }
}

const processTopVendorStats = async (db) => {
  const vendorCVECount = await db
    .collection("unified_cves")
    .aggregate([
      {
        $unwind: "$cpe",
      },
      {
        $group: {
          _id: "$cpe.vendor",
          count: { $count: {} },
        },
      },
      {
        $sort: { count: -1 },
      },
      {
        $limit: 4,
      },
    ])
    .toArray();
  vendorCVECount.shift();
  return vendorCVECount;
};

const updateTopVendorStats = async (db) => {
  const topVendorsDataCollection = createTopVendorsDataModel(db);

  logger.info("udpating radial Graph-3 data");
  const result = await processTopVendorStats(db);

    const status = await topVendorsDataCollection.updateOne(
      {_id: "home"},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
};

const getTopVendorStats = async (db) => {
  const topVendorsDataCollection = createTopVendorsDataModel(db);
  const result = await topVendorsDataCollection.findOne({_id: "home"});
  // if data exist for Home page
  if ( result ){
    logger.info("returning Cached top vendors Data for Home radial Graph");
    return result.data;
  }

  // process if cached not found
  logger.info("processing top vendors Data");
  return await processTopVendorStats(db);
};

// calculate exploited Stats
const processExploitedStats = async (db) => {
  const currentDate = new Date();
  const lastYear = new Date(
    currentDate.getFullYear() - 1,
    currentDate.getMonth(),
    currentDate.getDate()
  );
  const last3Months = new Date(
    currentDate.getFullYear(),
    currentDate.getMonth() - 3,
    currentDate.getDate()
  );
  const last6Months = new Date(
    currentDate.getFullYear(),
    currentDate.getMonth() - 6,
    currentDate.getDate()
  );

  const lastYearCount = await db.collection("unified_cves").countDocuments({
    is_exploited: true,
    published_at: {
      $gte: lastYear,
      $lt: currentDate,
    },
  });

  const last3MonthsCount = await db.collection("unified_cves").countDocuments({
    is_exploited: true,
    published_at: {
      $gte: last3Months,
      $lt: currentDate,
    },
  });

  const last6MonthsCount = await db.collection("unified_cves").countDocuments({
    is_exploited: true,
    published_at: {
      $gte: last6Months,
      $lt: currentDate,
    },
  });

  return {
    last7DaysCount: last3MonthsCount,
    last30DaysCount: last6MonthsCount,
    lastYearCount,
  };
};
// update CWE stats
const updateExploitedStats = async (db) => {
  const exploitedDataCollection = createExploitedDataModel(db);

  logger.info("udpating Line Graph data");
  const result = await processExploitedStats(db);

    const status = await exploitedDataCollection.updateOne(
      {_id: "home"},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
}
    
// get CWE stats
const getExploitedStats = async (db) => {
  const exploitedDataCollection = createExploitedDataModel(db);
  const result = await exploitedDataCollection.findOne({_id: "home"});
  // if data exist for Home page
  if ( result ){
    logger.info("returning Cached exploited cve counts Data for Home radial Graph");
    return result.data;
  }

  // process if cached not found
  logger.info("processing exploited cve counts Data");
  return await processExploitedStats(db);
}

const getTopProductStats = async (db) => {
  const productCVECount = await db
    .collection("unified_cves")
    .aggregate([
      {
        $unwind: "$cpe",
      },
      {
        $group: {
          _id: "$cpe.product",
          count: { $count: {} },
        },
      },
      {
        $sort: { count: -1 },
      },
      {
        $limit: 3,
      },
    ])
    .toArray();
  productCVECount;
  return productCVECount;
};

// process Fixes stats
const processFixesStats = async (db, vendor) => {
  const currentYear = new Date().getFullYear();
  const vendorName = vendor || "";
  const results = await db.collection("unified_cves").countDocuments({
    patch_url: { $exists: true, $ne: null, $ne: [] },
    "cpe.vendor": { $regex: new RegExp(vendorName, "i") },
     published_at: {
       $gte: new Date(`${currentYear - 1}-01-01`),
       $lt: new Date(`${currentYear + 1}-01-01`),
     },
  });
  const vendor_advisory = await db.collection("unified_cves").countDocuments({
    "cpe.vendor": { $regex: new RegExp(vendorName, "i") },
     published_at: {
       $gte: new Date(`${currentYear - 1}-01-01`),
       $lt: new Date(`${currentYear + 1}-01-01`),
     },
  });
  const totalCount = await db.collection("unified_cves").countDocuments({
    "cpe.vendor": { $regex: new RegExp(vendorName, "i") },
     published_at: {
       $gte: new Date(`${currentYear - 1}-01-01`),
       $lt: new Date(`${currentYear + 1}-01-01`),
     },
  });
  return {
    fixed: results,
    total: totalCount,
  };
};

// update Fixes stats
const updateFixesStats = async (db, vendor) => {
  const fixesDataCollection = createFixesDataModel(db);

  logger.info("udpating radial Graph-2 data");
  const result = await processFixesStats(db, vendor);

  if ( vendor === null || vendor === undefined ){
    const status = await fixesDataCollection.updateOne(
      {_id: "home"},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
  } else {
    const status = await fixesDataCollection.updateOne(
      {_id: vendor},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
  }
}
    
// get fixes stats
const getFixesStats = async (db, vendor) => {
  const fixesDataCollection = createFixesDataModel(db);
  // vendor check
  if ( vendor === undefined || vendor === null ){
    const result = await fixesDataCollection.findOne({_id: "home"});
    // if data exist for Home page
    if ( result ){
      logger.info("returning Cached Fixes Data for Home radial Graph");
      return result.data;
    }
  } else {
    const result = await fixesDataCollection.findOne({_id: vendor});
    // if data exist for a vendor
    if ( result ){
      const msg = `returning Cached Fixes Data for ${vendor}`;
      logger.info(msg);
      return result.data;
    }
  }

  // process if cached not found
  logger.info("processing exploited cve counts Data");
  return await processFixesStats(db, vendor);
}

// Function to get statistics on known exploited vulnerabilities
const getExploitedVulnerabilitiesStats = async (db) => {
  const stats = {
    sinceYesterday: await getCVECount(db, {
      exploited: true,
      updated_at: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    }),
    last7Days: await getCVECount(db, {
      exploited: true,
      updated_at: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
    }),
    last30Days: await getCVECount(db, {
      exploited: true,
      updated_at: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
    }),
  };

  return stats;
};

// const getCvesByVendorAndYear = async (db, vendor, year, page = 1, limit = 20) => {
//     const unifiedCollection = createUnifiedModel(db);

//     // Normalize vendor name for searching
//     const normalizedVendor = vendor.replace(/\s+/g, '').toLowerCase();

//     // Pagination logic
//     const skip = (page - 1) * limit;

//     const cves = await unifiedCollection.aggregate([
//         { $unwind: '$cpe' },  // Unwind the cpe array
//         {
//             $addFields: {
//                 normalizedVendor: {
//                     $replaceAll: {
//                         input: { $toLower: { $replaceAll: { input: '$cpe.vendor', find: ' ', replacement: '' } } },
//                         find: '',
//                         replacement: ''
//                     }
//                 }
//             }
//         },
//         { $match: { normalizedVendor: normalizedVendor } },  // Match the normalized vendor name
//         { $match: { published_at: { $gte: new Date(`${year}-01-01`), $lt: new Date(`${year + 1}-01-01`) } } }, // Match the specified year
//         {
//             $group: {
//                 _id: '$cve_id',
//                 description: { $first: '$description' }  // Take the first description found
//             }
//         },
//         { $project: { cve_id: '$_id', description: 1 } },  // Project the final fields
//         { $skip: skip },  // Skip for pagination
//         { $limit: limit }  // Limit results
//     ]).toArray();

//     return cves;
// };

const getCvesByVendorAndYear = async (
  db,
  vendor,
  year,
  page = 1,
  limit = 20
) => {
  const unifiedCollection = createUnifiedModel(db);

  // Normalize vendor name for searching
  const normalizedVendor = vendor.replace(/\s+/g, "").toLowerCase();

  // Pagination logic
  const skip = (page - 1) * limit;

  const cves = await unifiedCollection
    .aggregate([
      { $unwind: "$cpe" }, // Unwind the cpe array
      {
        $addFields: {
          normalizedVendor: {
            $replaceAll: {
              input: {
                $toLower: {
                  $replaceAll: {
                    input: "$cpe.vendor",
                    find: " ",
                    replacement: "",
                  },
                },
              },
              find: "",
              replacement: "",
            },
          },
        },
      },
      { $match: { normalizedVendor: normalizedVendor } }, // Match the normalized vendor name
      {
        $match: {
          published_at: {
            $gte: new Date(`${year}-01-01`),
            $lt: new Date(`${year + 1}-01-01`),
          },
        },
      }, // Match the specified year
      {
        $group: {
          _id: "$cve_id",
          description: { $first: "$description" },
          cvss_score: { $first: "$cvss_score" },
          epss_score: { $first: "$epss.epss_score" },
          published_at: { $first: "$published_at" },
          updated_at: { $first: "$updated_at" },
        },
      },
      {
        $project: {
          cve_id: "$_id",
          description: 1,
          max_cvss: "$cvss_score",
          epss_score: "$epss_score",
          published: "$published_at",
          updated: "$updated_at",
        },
      }, // Project the final fields
      { $skip: skip }, // Skip for pagination
      { $limit: limit }, // Limit results
    ])
    .toArray();

  return cves;
};

const generalSearchProductVersion = async (db, product, query) => {
  // Normalize the input query (e.g., remove spaces and lowercase)
  const normalizedQuery = query.replace(/\s+/g, "").toLowerCase();

  // Fetch the vendor and product data from the "search" collection
  const searchData = await getProductVersions(db, product);
    if (!searchData) {
    logger.info("No data found in the 'SEARCH' collection");
    return { versions: []};
  }

  const versions = searchData.map(item => item.version); // ✅ Use products
  

  // Create a map to store distinct products and vendors (key: normalized value, value: original value)
  const versionMap = new Map();

  // Iterate through vendors and add them to the map if they match the query
  // ✅ Use products to filter products
  // return versions;
  versions.forEach((version) => {
    const normalizedVersion = version.replace(/\s+/g, "").toLowerCase();
    if (normalizedVersion.includes(normalizedQuery)) {
      versionMap.set(normalizedVersion, version);
    }
  });

  // Convert maps back to arrays (containing only distinct values)
  const distinctVersion = Array.from(versionMap.values()).sort(
    // (a, b) => a.length - b.length
  );

  const limit = 5;

  return {
    versions: distinctVersion.slice(0, limit), // ✅ This now contains only cleaned products
  };
};

// More quick and easy way to autocomplete (uses seperate "search" collection which is updated once everyday.
const generalSearch = async (db, query) => {
  // Normalize the input query (e.g., remove spaces and lowercase)
  const normalizedQuery = query.replace(/\s+/g, "").toLowerCase();

  // Fetch the vendor and product data from the "search" collection
  const searchData = await db
    .collection("search")
    .findOne({ _id: "search_data" });

  if (!searchData) {
    logger.info("No data found in the 'SEARCH' collection");
    return { products: [], vendors: [], cveIds: [] };
  }

  const { vendors, products, cve_ids } = searchData; // ✅ Use products

  // Create a map to store distinct products and vendors (key: normalized value, value: original value)
  const productMap = new Map();
  const vendorMap = new Map();
  const cveIdMap = new Map();

  // console.log(
  //   vendors?.length || 0,
  //   products?.length || 0,
  //   cve_ids?.length || 0
  // );
  // Iterate through vendors and add them to the map if they match the query
  vendors.forEach((vendor) => {
    const normalizedVendor = vendor.replace(/\s+/g, "").toLowerCase();
    if (normalizedVendor.includes(normalizedQuery)) {
      vendorMap.set(normalizedVendor, vendor);
    }
  });

  // ✅ Use products to filter products
  products.forEach((product) => {
    const normalizedProduct = product.replace(/\s+/g, "").toLowerCase();
    if (normalizedProduct.includes(normalizedQuery)) {
      productMap.set(normalizedProduct, product);
    }
  });

  cve_ids.forEach((cve_id) => {
    const normalizedCveIds = cve_id.replace(/\s+/g, "").toLowerCase();
    if (normalizedCveIds.includes(normalizedQuery)) {
      cveIdMap.set(normalizedCveIds, cve_id);
    }
  });

  // Convert maps back to arrays (containing only distinct values)
  const distinctProducts = Array.from(productMap.values()).sort(
    (a, b) => a.length - b.length
  );
  const distinctVendors = Array.from(vendorMap.values()).sort(
    (a, b) => a.length - b.length
  );
  const distinctCveIds = Array.from(cveIdMap.values()).sort(
    (a, b) => a.length - b.length
  );

  const limit = 5;

  return {
    products: distinctProducts.slice(0, limit), // ✅ This now contains only cleaned products
    vendors: distinctVendors.slice(0, limit),
    cveIds: distinctCveIds.slice(0, limit),
  };
};

// results are renderd slow, affecting user experience
const oldGeneralSearch = async (db, query) => {
  const unifiedCollection = createUnifiedModel(db);

  // Normalize the input query (e.g., remove spaces and lowercase)
  const normalizedQuery = query.replace(/\s+/g, "").toLowerCase();

  const searchQuery = {
    $or: [
      // { cve_id: { $regex: query, $options: "i" } },
      // { description: { $regex: query, $options: "i" } },
      { "cpe.product": { $regex: query, $options: "i" } },
      { "cpe.vendor": { $regex: query, $options: "i" } },
    ],
  };

  const results = await unifiedCollection.find(searchQuery).toArray();

  // Create a map to store distinct products and vendors (key: normalized value, value: original value)
  const productMap = new Map();
  const vendorMap = new Map();

  results.forEach((result) => {
    result.cpe.forEach((cpeEntry) => {
      // Normalize vendor and product names
      const normalizedVendor = cpeEntry.vendor
        ? cpeEntry.vendor.replace(/\s+/g, "").toLowerCase()
        : "";
      const normalizedProduct = cpeEntry.product
        ? cpeEntry.product.replace(/\s+/g, "").toLowerCase()
        : "";

      // Add to map if it doesn't already exist (only unique normalized keys are stored)
      if (
        normalizedVendor.includes(normalizedQuery) &&
        !vendorMap.has(normalizedVendor)
      ) {
        vendorMap.set(normalizedVendor, cpeEntry.vendor); // Store the original vendor value
      }

      if (
        normalizedProduct.includes(normalizedQuery) &&
        !productMap.has(normalizedProduct)
      ) {
        productMap.set(normalizedProduct, cpeEntry.product); // Store the original product value
      }
    });
  });

  // Convert maps back to arrays (containing only distinct values)
  const products = Array.from(productMap.values());
  const vendors = Array.from(vendorMap.values());

  // return { products, vendors, cveIds: [] };
  return { products, vendors, cveIds: [] };
};

// calculate cvss data
const processCvssScoreRanges = async (db, vendor) => {
  const match = {
    cvss_score: { $exists: true, $ne: null },
  };

  if (vendor !== undefined && vendor !== null) {
    match["cpe.vendor"] = new RegExp(vendor, "i");
  }
  const scoreRanges = {
    "0-1": 0,
    "1-2": 0,
    "2-3": 0,
    "3-4": 0,
    "4-5": 0,
    "5-6": 0,
    "6-7": 0,
    "7-8": 0,
    "8-9": 0,
    "9+": 0,
  };

  // Use find with a projection to only fetch necessary fields
  const vulnerabilities = await db
    .collection("unified_cves")
    .aggregate([
      {
        $match: match,
      },
      {
        $project: {
          cvss_score: 1,
        },
      },
    ])
    .toArray();

  vulnerabilities.forEach((vulnerability) => {
    const cvssScore = vulnerability.cvss_score;

    if (cvssScore >= 0 && cvssScore < 1) scoreRanges["0-1"]++;
    else if (cvssScore >= 1 && cvssScore < 2) scoreRanges["1-2"]++;
    else if (cvssScore >= 2 && cvssScore < 3) scoreRanges["2-3"]++;
    else if (cvssScore >= 3 && cvssScore < 4) scoreRanges["3-4"]++;
    else if (cvssScore >= 4 && cvssScore < 5) scoreRanges["4-5"]++;
    else if (cvssScore >= 5 && cvssScore < 6) scoreRanges["5-6"]++;
    else if (cvssScore >= 6 && cvssScore < 7) scoreRanges["6-7"]++;
    else if (cvssScore >= 7 && cvssScore < 8) scoreRanges["7-8"]++;
    else if (cvssScore >= 8 && cvssScore < 9) scoreRanges["8-9"]++;
    else if (cvssScore >= 9) scoreRanges["9+"]++;
  });

  // Calculate total count
  const totalCount = vulnerabilities.length;

  // Calculate weighted average
  let weightedSum = 0;
  vulnerabilities.forEach((vulnerability) => {
    weightedSum += vulnerability.cvss_score;
  });

  const weightedAverage =
    totalCount > 0 ? (weightedSum / totalCount).toFixed(2) : 0;

  return {
    scoreRanges,
    totalCount,
    weightedAverage,
  };
};
  
// update CWE stats
const updateCvssScoreRanges = async (db, vendor) => {
  const cvssDataCollection = createCvssDataModel(db);

  logger.info("udpating Bar Graph data");
  const result = await processCvssScoreRanges(db, vendor);

  if ( vendor === null || vendor === undefined ){
    const status = await cvssDataCollection.updateOne(
      {_id: "home"},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
  } else {
    const status = await cvssDataCollection.updateOne(
      {_id: vendor},
      {$set: {data: result, updated_at: new Date() } },
      { upsert: true }
    );
    const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
    logger.info(msg);
  }
}
    
// get CWE stats
const getCvssScoreRanges = async (db, vendor) => {
  const cvssDataCollection = createCvssDataModel(db);
  // vendor check
  if ( vendor === undefined || vendor === null ){
    // console.log("checking cached collection ");
    const result = await cvssDataCollection.findOne({_id: "home"});
    // if data exist for Home page
    if ( result ){
      logger.info("returning Cached CVSS Data for Home line Graph");
      return result.data;
    }
  } else {
    const result = await cvssDataCollection.findOne({_id: vendor});
    // if data exist for a vendor
    if ( result ){
      const msg = `returning Cached CVSS Data for ${vendor}`;
      logger.info(msg);
      return result.data;
    }
  }

  // process if cached not found
  logger.info("processing CVSS Data");
  const result = await processCvssScoreRanges(db, vendor);
  // console.log(result);

  return result
}

const getVersionDetails = async (db, product, version) => {
  const unifiedCollection = createUnifiedModel(db);

  if( version ='All' ){
    const versionDetails = await unifiedCollection.aggregate([
      {
        "$match": 
        {
          "cpe.product": product,
        }
      },
      { $sort: { published_at: -1 } },
    ])
  }

  const versionDetails = await unifiedCollection.findOne(
    {
      "cpe.product": product,
      "cpe.versions": {
        $elemMatch: {
          $or: [
            { version: version },
            {
              version: { $lte: version },
              $or: [
                { lessThan: { $gt: version } },
                { lessThanOrEqual: { $gte: version } },
              ],
            },
          ],
        },
      },
    },
    {
      projection: {
        cpe: 1,
      },
    }
  );

  if (!versionDetails) {
    return null;
  }

  const cpe = versionDetails.cpe.find((c) => c.product === product);
  const versionInfo = cpe.versions.find(
    (v) =>
      v.version === version ||
      (semver.lte(v.version, version) &&
        (!v.lessThan || semver.gt(v.lessThan, version)) &&
        (!v.lessThanOrEqual || semver.gte(v.lessThanOrEqual, version)))
  );

  return {
    versionNames: [
      `${cpe.vendor} ${cpe.product} ${version}`,
      `cpe:2.3:a:${cpe.vendor.toLowerCase()}:${cpe.product.toLowerCase()}:${version}:*:*:*:*:*:*:*`,
      `cpe:/a:${cpe.vendor.toLowerCase()}:${cpe.product.toLowerCase()}:${version}`,
    ],
    productInformation: {
      vendor: `https://www.${cpe.vendor.toLowerCase()}.com/`,
      product: `https://${cpe.product.toLowerCase()}.${cpe.vendor.toLowerCase()}.com/`,
    },
    affectedRange: getVersionRange(
      versionInfo.version,
      versionInfo.lessThan,
      versionInfo.lessThanOrEqual
    ),
  };
};

// Function to compare version strings
const newCompareVersions = (a, b) => {
  const versionA = a.version.split(" ").pop(); // Get the version part
  const versionB = b.version.split(" ").pop(); // Get the version part

  // Split the version strings into parts for comparison
  const partsA = versionA.split(".").map(Number);
  const partsB = versionB.split(".").map(Number);

  // Compare each part of the version
  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const numA = partsA[i] || 0; // Default to 0 if part is missing
    const numB = partsB[i] || 0; // Default to 0 if part is missing

    if (numA < numB) return -1;
    if (numA > numB) return 1;
  }

  return 0; // Versions are equal
};

const compareVersions = (a, b) => {
  const cleanA = a.version.replace(/[^0-9.]/g, "");
  const cleanB = b.version.replace(/[^0-9.]/g, "");

  const partsA = cleanA.split(".").map(Number);
  const partsB = cleanB.split(".").map(Number);

  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const partA = partsA[i] || 0;
    const partB = partsB[i] || 0;
    if (partA > partB) return 1;
    if (partA < partB) return -1;
  }
  return 0;
};

const getProductVersions = async (db, product) => {
  const unifiedCollection = createUnifiedModel(db);

  const vulnerabilities = await unifiedCollection
    .aggregate([
      { $unwind: "$cpe" },
      { $match: { "cpe.product": { $regex: new RegExp(product, "i") } } },
      { $unwind: "$cpe.versions" },
      {
        $group: {
          //_id: "$cpe.versions.versionStartIncluding", // Group by the version
          _id: "$cpe.versions.version", // Group by the version
          //_id: "$cpe.version", // Group by the version
          count: { $sum: 1 }, // Count occurrences of each version
        },
      },
      {
        $project: {
          _id: 0, // Exclude the default _id field
          version: "$_id", // Rename _id to version
          count: 1, // Include the count
        },
      },
    ])
    .toArray();

  // console.log("fish0", product, vulnerabilities);

  if (vulnerabilities.length === 0 || vulnerabilities[0].count === 0) {
    return [
      {
        version: "All versions",
        vulnerabilityCount: await unifiedCollection.countDocuments({
          "cpe.product": product,
        }),
        affectedRange: "All versions",
      },
    ];
  }

  const versions = vulnerabilities; // Now vulnerabilities is an array of version counts
  //const totalCount = versions.reduce((sum, v) => sum + v.totalCount, 0); // Calculate total count

  // Process versions and create entries
  let processedVersions = versions.reduce((acc, v) => {
    if (v.version !== "N/A" && v.version) {
      if (v.version.includes(" to ")) {
        // Handle range format "X.X to Y.Y"
        const [start, end] = v.version.split(" to ");
        acc.push({
          version: start,
          rangeEnd: end,
          count: v.count, // Include the count for this version
        });
      } else {
        acc.push({
          version: v.version,
          count: v.count, // Include the count for this version
        });
      }
    } else if (v.lessThan) {
      // For entries with only lessThan, create two version entries
      const previousVersion =
        acc.length > 0 ? acc[acc.length - 1].version : "0.0.0";
      acc.push({
        version: previousVersion,
        lessThan: v.lessThan,
        count: v.count,
      });
      acc.push({
        version: v.lessThan,
        isLessThan: true,
        count: v.count,
      });
    }
    return acc;
  }, []);

  // Remove duplicates
  processedVersions = [...new Set(processedVersions.map(JSON.stringify))].map(
    JSON.parse
  );

  // Sort using custom comparison function
  processedVersions.sort(compareVersions);
  processedVersions.reverse();

  // Create final version entries
  return processedVersions.map((v) => {
    // console.log("fish1", v.count);
    return {
      version: v.version,
      vulnerabilityCount: v.count, // We don't have individual counts, so using total
      affectedRange: v.rangeEnd
        ? `From ${v.version} to ${v.rangeEnd}`
        : "Specific version",
      isLessThan: v.isLessThan || false, // Include isLessThan if applicable
    };
  });
};

// Update getVersionRange function to handle non-standard version formats
const getVersionRange = (version, lessThan, lessThanOrEqual) => {
  if (version === "N/A") {
    return "All versions";
  }
  let range = `>= ${version}`;
  if (lessThan) {
    range += ` < ${lessThan}`;
  } else if (lessThanOrEqual) {
    range += ` <= ${lessThanOrEqual}`;
  }
  return range;
};

const getProductVersionVulnerabilities = async (db, product, version) => {
  const unifiedCollection = createUnifiedModel(db);

  // First, get the product versions to determine the correct range
  const productVersions = await getProductVersions(db, product);

  // Find the current version entry
  const currentVersionEntry = productVersions.find(
    (v) => v.version === version
  );

  if (!currentVersionEntry) {
    return []; // No vulnerabilities if the version doesn't exist
  }

  let match;
  if (currentVersionEntry.affectedRange === "All versions") {
    match = { "cpe.product": product };
  } else if (currentVersionEntry.affectedRange.startsWith("<")) {
    // For "less than" versions, we need to get all vulnerabilities up to this version
    const lessThanVersion = currentVersionEntry.affectedRange.split(" ")[1];
    match = {
      "cpe.product": product,
      $or: [
        { "cpe.versions.version": "N/A" },
        { "cpe.versions.version": { $lt: lessThanVersion } },
        { "cpe.versions.lessThan": { $gt: version } },
        { "cpe.versions.lessThanOrEqual": { $gte: version } },
      ],
    };
  } else if (currentVersionEntry.affectedRange.includes(" to ")) {
    // For range versions "X.X to Y.Y"
    const [rangeStart, rangeEnd] =
      currentVersionEntry.affectedRange.split(" to ");
    match = {
      "cpe.product": product,
      $or: [
        {
          "cpe.versions.version": { $regex: `^${rangeStart} to ${rangeEnd}$` },
        },
        {
          $and: [
            { "cpe.versions.version": { $gte: rangeStart } },
            { "cpe.versions.version": { $lte: rangeEnd } },
          ],
        },
      ],
    };
  } else {
    // For regular versions, use the original logic
    match = {
      "cpe.product": product,
      $or: [
        { "cpe.versions.version": version },
        {
          "cpe.versions.version": { $lte: version },
          $or: [
            { "cpe.versions.lessThan": { $gt: version } },
            { "cpe.versions.lessThanOrEqual": { $gte: version } },
          ],
        },
      ],
    };
  }

  const vulnerabilities = await unifiedCollection
    .aggregate([
      { $match: match },
      { $unwind: "$cpe" },
      { $unwind: "$cpe.versions" },
      {
        $group: {
          _id: "$cve_id",
          description: { $first: "$description" },
          cvss_score: { $first: "$cvss_score" },
          epss_score: { $first: "$epss.epss_score" },
          published_at: { $first: "$published_at" },
          updated_at: { $first: "$updated_at" },
        },
      },
    ])
    .toArray();

  return vulnerabilities.map((v) => ({
    cve_id: v._id,
    description: v.description,
    max_cvss: v.cvss_score,
    epss_score: v.epss_score,
    published: v.published_at,
    updated: v.updated_at,
  }));
};

const getFilteredProductVulnerabilities = async (
  db,
  product,
  version,
  page = 1,
  limit = 20,
  filters = {}
) => {
  const unifiedCollection = createUnifiedModel(db);
  const skip = (page - 1) * limit;

  // First, get the product versions to determine the correct range
  const productVersions = await getProductVersions(db, product);

  // Find the current version entry
  const currentVersionEntry = productVersions.find((v) => {
    if (version.includes(" to ")) {
      // For range versions, match the exact range
      return v.affectedRange === version;
    } else if (version.startsWith("< ")) {
      // For "less than" versions, match the exact "less than" range
      return v.affectedRange === version;
    }
    return v.version === version;
  });
  // console.log("fish 4", currentVersionEntry);

  if (!currentVersionEntry && version !== 'All') {
    return {
      vulnerabilities: [],
      pagination: {
        total: 0,
        page,
        limit,
        pages: 0,
      },
    };
  }

  // Base match criteria
  let match = {
    "cpe.product": { $regex: new RegExp(product, "i") },
  };

  // Add year filter if provided and not "all"
  if (filters.year && filters.year !== "all") {
    match.published_at = {
      $gte: new Date(`${filters.year}-01-01`),
      $lt: new Date(`${parseInt(filters.year) + 1}-01-01`),
    };
  }

  // Add month filter if provided
  if (filters.month && filters.month !== "all") {
    const startDate = new Date(
      `${filters.year}-${filters.month}-01T00:00:00.000Z`
    );
    const endDate = new Date(startDate);
    endDate.setMonth(startDate.getMonth() + 1);
    match.published_at = {
      $gte: startDate,
      $lt: endDate,
    };
  }
  // console.log("fish 4", match);

  // Add CVSS score filter
  if (filters.minCvss) {
    match.cvss_score = { $gte: parseFloat(filters.minCvss) };
  }

  // Add version-specific matching logic
  if (version === 'All'){
  }
  else if (currentVersionEntry.affectedRange === "All versions") {
    //console.log("fish5");
    // No additional version criteria needed
  } else if (currentVersionEntry.affectedRange.startsWith("< ")) {
    const lessThanVersion = currentVersionEntry.affectedRange.split(" ")[1];
    match.$or = [
      { "cpe.versions.version": "N/A" },
      { "cpe.versions.version": { $lt: lessThanVersion } },
      { "cpe.versions.lessThan": { $gt: version } },
      { "cpe.versions.lessThanOrEqual": { $gte: version } },
    ];
  } else if (currentVersionEntry.affectedRange.includes(" to ")) {
    const [rangeStart, rangeEnd] = currentVersionEntry.affectedRange
      .split(" to ")
      .map((v) => v.trim());
    match.$or = [
      { "cpe.versions.version": currentVersionEntry.affectedRange }, // Exact range match
      {
        $and: [
          { "cpe.versions.version": { $gte: rangeStart } },
          { "cpe.versions.version": { $lte: rangeEnd } },
        ],
      },
      {
        "cpe.versions.version": { $lte: rangeEnd },
        "cpe.versions.lessThan": { $gt: rangeStart },
      },
    ];
  } else {
    // For regular versions
    match.$or = [
      { "cpe.versions.version": version },
      {
        "cpe.versions.version": { $lte: version },
        $or: [
          { "cpe.versions.lessThan": { $gt: version } },
          { "cpe.versions.lessThanOrEqual": { $gte: version } },
        ],
      },
    ];
  }

  // Add date filters
  // if (filters.year || filters.month) {
  //   const dateFilter = {};
  //   if (filters.year) {
  //     dateFilter.$gte = new Date(`${filters.year}-01-01T00:00:00.000Z`);
  //     dateFilter.$lt = new Date(
  //       `${parseInt(filters.year) + 1}-01-01T00:00:00.000Z`
  //     );
  //   }
  //   if (filters.month) {
  //     const startDate = new Date(
  //       `${filters.year}-${filters.month}-01T00:00:00.000Z`
  //     );
  //     const endDate = new Date(startDate);
  //     endDate.setMonth(startDate.getMonth() + 1);
  //     dateFilter.$gte = startDate;
  //     dateFilter.$lt = endDate;
  //   }
  //   match.published_at = dateFilter;
  // }

  // Add CVSS score filter
  // if (filters.minCvss) {
  //   match.cvss_score = { $gte: parseFloat(filters.minCvss) };
  // }

  // Determine sort field and direction
  let sortField = { published_at: -1 }; // default sort
  if (filters.sortBy) {
    const [field, direction] = filters.sortBy.split(":");
    const sortDirection = direction === "asc" ? 1 : -1;

    switch (field) {
      case "publishDate":
        sortField = { published_at: sortDirection };
        break;
      case "updateDate":
        sortField = { updated_at: sortDirection };
        break;
      case "cveId":
        sortField = { cve_id: sortDirection };
        break;
      case "cvssScore":
        sortField = { cvss_score: sortDirection };
        break;
      case "epssScore":
        sortField = { "epss.epss_score": sortDirection };
        break;
    }
  }

  // Get total count for pagination
  const total = await unifiedCollection.countDocuments(match);

  const pipeline = [
    { $match: match },
    { $sort: sortField },
    { $skip: skip },
    { $limit: limit },
    {
      $project: {
        cve_id: 1,
        description: 1,
        cvss_score: 1,
        "epss.epss_score": 1,
        published_at: 1,
        updated_at: 1,
      },
    },
  ];

  // console.log("fish0", pipeline[0]["$match"]);

  const vulnerabilities = await unifiedCollection.aggregate(pipeline).toArray();

  return {
    vulnerabilities,
    pagination: {
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    },
  };
};

const getFilteredVendorVulnerabilities = async (
  db,
  vendor,
  year,
  page = 1,
  limit = 20,
  filters = {}
) => {
  const unifiedCollection = createUnifiedModel(db);
  const skip = (page - 1) * limit;

  // Base match criteria
  let match = {
    "cpe.vendor": { $regex: new RegExp(vendor, "i") },
  };

  // Add year filter if provided and not "all"
  if (year && year !== "all") {
    match.published_at = {
      $gte: new Date(`${year}-01-01`),
      $lt: new Date(`${parseInt(year) + 1}-01-01`),
    };
  }

  // Add month filter if provided
  if (filters.month && filters.month !== "all") {
    const startDate = new Date(`${year}-${filters.month}-01T00:00:00.000Z`);
    const endDate = new Date(startDate);
    endDate.setMonth(startDate.getMonth() + 1);
    match.published_at = {
      $gte: startDate,
      $lt: endDate,
    };
  }

  // Add CVSS score filter
  if (filters.minCvss) {
    match.cvss_score = { $gte: parseFloat(filters.minCvss) };
  }

  // Determine sort field and direction
  let sortField = { published_at: -1 }; // default sort
  if (filters.sortBy) {
    const [field, direction] = filters.sortBy.split(":");
    const sortDirection = direction === "asc" ? 1 : -1;

    switch (field) {
      case "publishDate":
        sortField = { published_at: sortDirection };
        break;
      case "updateDate":
        sortField = { updated_at: sortDirection };
        break;
      case "cveId":
        sortField = { cve_id: sortDirection };
        break;
      case "cvssScore":
        sortField = { cvss_score: sortDirection };
        break;
      case "epssScore":
        sortField = { "epss.epss_score": sortDirection };
        break;
    }
  }

  const pipeline = [
    { $match: match },
    { $sort: sortField },
    { $skip: skip },
    { $limit: limit },
    {
      $project: {
        cve_id: 1,
        description: 1,
        cvss_score: 1,
        "epss.epss_score": 1,
        published_at: 1,
        updated_at: 1,
      },
    },
  ];

  // Get total count for pagination
  const total = await unifiedCollection.countDocuments(match);
  const vulnerabilities = await unifiedCollection.aggregate(pipeline).toArray();

  return {
    vulnerabilities,
    pagination: {
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    },
  };
};

// create a function for getting the unique vendors from the database and return them as a response to the client alphabetically sorted in ascending order
// (i.e., from A to Z).
// New functions to add to your existing code

const getAlphabeticalVendors = async (db, letter, page = 1, limit = 20) => {
  const unifiedCollection = createUnifiedModel(db);
  const skip = (page - 1) * limit;

  // Create match condition based on whether a letter is provided
  const matchCondition = letter
    ? { "cpe.vendor": { $regex: `^${letter}`, $options: "i" } }
    : {};

  // Get total count for pagination
  const totalCount = await unifiedCollection
    .aggregate([
      { $unwind: "$cpe" },
      { $match: matchCondition },
      { $group: { _id: "$cpe.vendor" } },
      { $count: "total" },
    ])
    .toArray();

  const total = totalCount[0]?.total || 0;

  // Get paginated vendors with product count
  const vendors = await unifiedCollection
    .aggregate([
      { $unwind: "$cpe" },
      { $match: matchCondition },
      {
        $group: {
          _id: "$cpe.vendor",
          vulnerabilityCount: { $sum: 1 },
          latestUpdate: { $max: "$updated_at" },
          uniqueProducts: { $addToSet: "$cpe.product" },
        },
      },
      { $sort: { _id: 1 } },
      { $skip: skip },
      { $limit: limit },
      {
        $project: {
          vendor: "$_id",
          vulnerabilityCount: 1,
          lastUpdated: "$latestUpdate",
          productCount: { $size: "$uniqueProducts" },
          _id: 0,
        },
      },
    ])
    .toArray();

  return {
    vendors,
    pagination: {
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    },
  };
};
const getAlphabeticalProducts = async (db, letter, page = 1, limit = 20) => {
  const unifiedCollection = createUnifiedModel(db);
  const skip = (page - 1) * limit;

  // Create match condition based on whether a letter is provided
  const matchCondition = letter
    ? { "cpe.product": { $regex: `^${letter}`, $options: "i" } }
    : {};

  // Get total count for pagination
  const totalCount = await unifiedCollection
    .aggregate([
      { $unwind: "$cpe" },
      { $match: matchCondition },
      { $group: { _id: "$cpe.product" } },
      { $count: "total" },
    ])
    .toArray();

  const total = totalCount[0]?.total || 0;

  // Get paginated products
  const products = await unifiedCollection
    .aggregate([
      { $unwind: "$cpe" },
      { $match: matchCondition },
      {
        $group: {
          _id: "$cpe.product",
          vendor: { $first: "$cpe.vendor" },
          count: { $sum: 1 },
          latestUpdate: { $max: "$updated_at" },
        },
      },
      { $sort: { _id: 1 } },
      { $skip: skip },
      { $limit: limit },
      {
        $project: {
          product: "$_id",
          vendor: 1,
          vulnerabilityCount: "$count",
          lastUpdated: "$latestUpdate",
          _id: 0,
        },
      },
    ])
    .toArray();

  return {
    products,
    pagination: {
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    },
  };
};

const getCWEStatsFast = async (db, vendor) => {
  if (vendor !== undefined && vendor !== null) {
    const vendorName = vendor.replace(/[-\/\\^$.*+?()[\]{}|]/g, "\\$&");
    let res = await db.collection("cwe").findOne({ _id: vendorName });

    if (res !== null) {
      logger.info("response Found fast");
      return res.data;
    } else {
      logger.info("response Found slow");
      res = await getCWEStats(db, vendorName);
      return res;
    }
  } else {
    let res = await db.collection("cwe").findOne({ _id: "home-weakness" });
    if (res !== null) {
      const output = [];
      // Iterate over the years
      res.data.forEach((yearData) => {
        const year = yearData.year;
        const yearTotal = Object.values(yearData.data).reduce(
          (sum, value) => sum + value,
          0
        );
        const row = {
          date: year.toString(),
          Total: yearTotal,
          Overflow: yearData.data.Overflow,
          "Memory Corruption": yearData.data["Memory Corruption"],
          "SQL Injection": yearData.data["SQL Injection"],
          XSS: yearData.data.XSS,
          "Directory Traversal": yearData.data["Directory Traversal"],
          "File Inclusion": yearData.data["File Inclusion"],
          CSRF: yearData.data.CSRF,
          XXE: yearData.data.XXE,
          SSRF: yearData.data.SSRF,
        };
        output.push(row);
      });

      logger.info("response Found fast");
      return output;
    } else {
      logger.info("response Found slow");
      res = await getCWEStats(db);
      return res;
    }
  }
};

const getCvssScoreRangesFast = async (db, vendor) => {
  if (vendor !== undefined && vendor !== null) {
    const vendorName = vendor.replace(/[-\/\\^$.*+?()[\]{}|]/g, "\\$&");
    let res = await db.collection("cvss").findOne({ _id: vendorName });

    if (res !== null) {
      logger.info("response Found fast");
      return res.data;
    } else {
      logger.info("response Found slow");
      res = await getCvssScoreRanges(db, vendorName);
      return res;
    }
  } else {
    let res = await db.collection("cvss").findOne({ _id: "home-cvss" });
    if (res !== null) {
      logger.info("response Found fast");
      return res.data;
    } else {
      logger.info("response Found slow");
      res = await getCvssScoreRanges(db);
      return res;
    }
  }
};

const getVendorStats = async (db, vendor) => {
  const unifiedCollection = createUnifiedModel(db);

  const pipeline = [
    { $match: { "cpe.vendor": { $regex: new RegExp(vendor, "i") } } },
    {
      $group: {
        _id: null,
        totalVulnerabilities: { $sum: 1 },
        vulnerabilitiesExploited: { $sum: { $cond: ["$is_exploited", 1, 0] } },
        patchesAvailable: {
          $sum: { $cond: [{ $gt: ["$vendor_advisory", []] }, 1, 0] },
        },
        averageCvssScore: { $avg: "$cvss_score" },
        // Example metric: count of vulnerabilities with high severity
        highSeverityCount: {
          $sum: { $cond: [{ $eq: ["$severity", "HIGH"] }, 1, 0] },
        },
      },
    },
    {
      $project: {
        _id: 0,
        totalVulnerabilities: 1,
        vulnerabilitiesExploited: 1,
        patchesAvailable: 1,
        averageCvssScore: 1,
        highSeverityCount: 1,
      },
    },
  ];

  const result = await unifiedCollection.aggregate(pipeline).toArray();
  return result[0] || {};
};

// Fetch CVEs for the feed
const getFeed = async (limit, page, watchlistName = null, filters = []) => {
  const token = localStorage.getItem("accessToken");
  if (!token) throw new Error("Authentication token not found");

  try {
    // Construct query parameters
    const queryParams = new URLSearchParams();
    queryParams.append("page", page);
    queryParams.append("limit", limit);

    if (watchlistName) {
      queryParams.append("watchlist", watchlistName);
    }

    if (filters.length > 0) {
      queryParams.append("filters", JSON.stringify(filters));
    }

    // Use Axios timeout to prevent hanging requests
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/feed?${queryParams.toString()}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        timeout: 15000, // 15 second timeout
      }
    );

    // Validate response structure
    if (!response.data || !response.data.success) {
      console.error("Invalid feed response:", response.data);
      throw new Error("Received invalid response from server");
    }

    return response.data;
  } catch (err) {
    console.error("Feed fetch error:", err);

    // More specific error messages
    if (err.response?.status === 401) {
      throw new Error("Authentication expired. Please log in again.");
    } else if (err.response?.status === 500) {
      throw new Error(
        `Server error: ${err.response.data?.message || "Unknown error"}`
      );
    } else if (err.code === "ECONNABORTED") {
      throw new Error(
        "Request timed out. The server may be experiencing high load."
      );
    }

    throw err;
  }
};

// Fetch filtered CVEs
const getFilteredCves = async (db, filters) => {
  const unifiedCollection = createUnifiedModel(db);

  // Build the match criteria based on the filters
  const criteriaArray = filters.map((f) => {
    return {
      $or: [
        { "cpe.vendor": { $regex: f, $options: "i" } },
        { "cpe.product": { $regex: f, $options: "i" } },
      ],
    };
  });
  const matchCriteria = criteriaArray.length > 0 ? { $or: criteriaArray } : {};

  const cves = await unifiedCollection
    .aggregate([
      { $unwind: "$cpe" },
      { $match: matchCriteria },
      {
        $group: {
          _id: "$cve_id",
          cve_id: { $first: "$cve_id" },
          description: { $first: "$description" },
          cvss_score: { $first: "$cvss_score" },
          published_at: { $first: "$published_at" },
          updated_at: { $first: "$updated_at" },
        },
      },
      { $sort: { published_at: -1 } },
    ])
    .toArray();

  return cves;
};

const getTopVendorByYear = async (db, year) => {
  try {
    const currentYear = new Date().getFullYear(); // Get the current year dynamically

    const pipeline = [
      {
        $match: {
          published_at: {
            $gte: new Date(`${currentYear}-01-01T00:00:00Z`),
            $lt: new Date(`${currentYear + 1}-01-01T00:00:00Z`),
          },
        },
      },
      {
        $unwind: "$cpe",
      },
      {
        $group: {
          _id: "$cpe.vendor",
          count: { $sum: 1 },
        },
      },
      {
        $sort: { count: -1 },
      },
      {
        $limit: 1,
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();
    // console.log("cat 0", result);

    return result.length > 0
      ? result[0]
      : { message: "No CVEs found for the current year." };
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching top vendor");
  }
};

const getTopVendorByFixes = async (db) => {
  try {
    let year = new Date().getFullYear();
    let result = [];

    while (year >= 2000) {
      const pipeline = [
        {
          $match: {
            published_at: {
              $gte: new Date(`${year}-01-01T00:00:00Z`),
              $lt: new Date(`${year + 1}-01-01T00:00:00Z`),
            },
            patch_url: { $exists: true, $ne: [] },
          },
        },
        { $unwind: "$patch_url" },
        { $unwind: "$cpe" },
        {
          $group: {
            _id: "$cpe.vendor",
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
        { $limit: 1 },
      ];

      result = await db
        .collection("unified_cves")
        .aggregate(pipeline)
        .toArray();

      if (result.length > 0) break;

      year--;
    }

    // console.log("cat 1", result);

    return result.length > 0
      ? result[0]
      : { message: "No fixes found in available data." };
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching top vendor by fixes");
  }
};

const getAverageCVEsPerYear = async (db) => {
  try {
    const pipeline = [
      {
        $group: {
          _id: { $year: "$published_at" },
          total_cves: { $sum: 1 },
        },
      },
      {
        $group: {
          _id: null,
          avg_cves: { $avg: "$total_cves" },
        },
      },
      {
        $project: {
          _id: "average_cves_per_year",
          count: { $round: ["$avg_cves", 0] }, // Round to 0 decimal places
        },
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    // console.log("cat 2", result);
    return result.length > 0 ? result[0] : { message: "No CVEs found." };
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching average CVEs per year");
  }
};

const getHighRiskVendorCount = async (db) => {
  try {
    const pipeline = [
      {
        $match: {
          cvss_score: { $gt: 7 },
        },
      },
      {
        $unwind: "$cpe",
      },
      {
        $group: {
          _id: "$cpe.vendor",
        },
      },
      {
        $count: "Highrisk_Vendors",
      },
      {
        $project: {
          _id: "Highrisk_Vendors", // Set _id to the desired string
          count: "$Highrisk_Vendors", // Rename the count field
        },
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    // console.log("cat 3", result);

    return result.length > 0 ? result[0] : { Highrisk_Vendors: 0 };
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching high-risk vendor count");
  }
};

const getTotalVendors = async (db) => {
  try {
    const pipeline = [
      {
        $unwind: "$cpe",
      },
      {
        $group: {
          _id: "$cpe.vendor",
        },
      },
      {
        $count: "total_vendors",
      },
      {
        $project: {
          _id: "total_vendors", // Set _id to the desired string
          count: "$total_vendors", // Rename the count field
        },
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    // console.log("cat 4", result);
    return result.length > 0 ? result[0] : { total_vendors: 0 };
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching total number of vendors");
  }
};

const getProductWithMostCVEs = async (db) => {
  try {
    const pipeline = [
      {
        $unwind: "$cpe", // Unwind the CPE array to process each product separately
      },
      {
        $match: {
          "cpe.product": {
            $ne: "n/a", // Exclude invalid product names
            $ne: null,
            $ne: "",
            $ne: "*",
            $ne: "-",
            $ne: ".",
            $not: { $in: ["n/a", null, "", "*", "-", ".", "?"] },
            $regex: /^[a-z0-9][a-z0-9_\-]{1,}$/i, // Ensure valid product names
          },
        },
      },
      {
        $group: {
          _id: "$cpe.product", // Group by product name
          vulnerability_count: { $sum: 1 }, // Count the number of vulnerabilities
        },
      },
      {
        $sort: { vulnerability_count: -1 }, // Sort by the highest vulnerability count
      },
      {
        $limit: 1, // Limit to the top product
      },
    ];

    const result = await db.collection("unified_cves").aggregate(pipeline).toArray();

    if (result.length > 0) {
      const topProduct = result[0];
      // Debug log for the product name and count
      // console.log(`DEBUG: Product with Most CVEs: ${topProduct._id}, Count: ${topProduct.vulnerability_count}`);
      return topProduct;
    } else {
      return { message: "No valid product vulnerabilities found." };
    }
  } catch (error) {
    console.error("ERROR in getProductWithMostCVEs:", error);
    throw new Error("Error fetching product with most vulnerabilities");
  }
};


const getTopProductByFixes = async (db) => {
  try {
    const pipeline = [
      {
        $match: {
          $or: [
            { patch_url: { $exists: true, $ne: null, $ne: [] } },
            { vendor_advisory: { $exists: true, $ne: null, $ne: [] } }
          ],
          vulnerable_cpe: { $exists: true, $ne: null, $ne: [] } // Ensure vulnerable_cpe exists and is not empty
        }
      },
      {
        $unwind: "$vulnerable_cpe" 
      },
      {
        $addFields: {
          cpe_parts: { $split: ["$vulnerable_cpe", ":"] } 
        }
      },
      {
        $addFields: {
          product_name: { $arrayElemAt: ["$cpe_parts", 4] } 
        }
      },
      {
        $match: {
          product_name: {
            $ne: "n/a", 
            $ne: null,
            $ne: "",
            $ne: "*",
            $ne: "-",
            $ne: ".",
            $not: { $in: ["n/a", null, "", "*", "-", ".", "?"] },
            $regex: /^[a-z0-9][a-z0-9_\-]{1,}$/i // Ensure product name has valid characters
          }
        }
      },
      {
        $group: {
          _id: "$product_name", 
          count: { $sum: 1 } 
        }
      },
      { $sort: { count: -1 } }, 
      { $limit: 1 } 
    ];

    const result = await db.collection("unified_cves").aggregate(pipeline).toArray();

    
    // console.log("DEBUG: Top Product by Fixes:", result);

    return result.length > 0
      ? { product: result[0]._id, fix_count: result[0].count } 
      : { message: "No valid products with fixes found in available data." };
  } catch (error) {
    console.error("ERROR in getTopProductByFixes:", error);
    throw new Error(`Error fetching top product by fixes: ${error.message}`);
  }
};


const getAverageProductCVEsPerYear = async (db) => {
  try {
    const pipeline = [
      {
        $group: {
          _id: { $year: "$published_at" }, // Group by year
          total_cves: { $sum: 1 }, // Count total CVEs in each year
        },
      },
      {
        $group: {
          _id: null,
          total_cves_over_years: { $sum: "$total_cves" }, // Sum of all yearly CVEs
          total_years: { $sum: 1 }, // Count distinct years
        },
      },
      {
        $project: {
          _id: 0,
          average_cves_per_year: {
            $round: [
              { $divide: ["$total_cves_over_years", "$total_years"] },
              0,
            ],
          }, // Calculate and round the average
        },
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    return result.length > 0 ? result[0] : { message: "No CVEs found." };
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching average CVEs reported per year");
  }
};

const getTotalProducts = async (db) => {
  try {
    const pipeline = [
      {
        $unwind: "$cpe", // Unwind CPE array to process each product separately
      },
      {
        $group: {
          _id: "$cpe.product", // Group by unique product names
        },
      },
      {
        $count: "total_products", // Count the total number of unique products
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    return result.length > 0
      ? { total_products: result[0].total_products }
      : { total_products: 0 };
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching total number of products");
  }
};

const getHighRiskProductCount = async (db) => {
  try {
    const pipeline = [
      {
        $match: {
          cvss_score: { $gt: 7 }, // Only include vulnerabilities with CVSS > 7
        },
      },
      {
        $unwind: "$cpe", // Unwind CPE array to process each product separately
      },
      {
        $group: {
          _id: "$cpe.product", // Group by unique product names
        },
      },
      {
        $count: "highrisk_products", // Count the total number of unique high-risk products
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    return result.length > 0
      ? { highrisk_products: result[0].highrisk_products }
      : { highrisk_products: 0 };
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching high-risk product count");
  }
};

const getDailyCVEsForProductVersion = async (
  db,
  year,
  month,
  product,
  version
) => {
  try {
    const startDate = new Date(year, month - 1, 1); // First day of the month
    const endDate = new Date(year, month, 0); // Last day of the month
    const daysInMonth = endDate.getDate(); // Get total number of days in the month

    const pipeline = [
      {
        $match: {
          published_at: {
            $gte: startDate,
            $lt: new Date(year, month, 1), // First day of next month
          },
          "cpe.product": product, // Filter by product name
          "cpe.version": version, // Filter by version
        },
      },
      {
        $group: {
          _id: { $dayOfMonth: "$published_at" }, // Group by day
          cve_count: { $sum: 1 },
        },
      },
      {
        $sort: { _id: 1 }, // Sort by day
      },
      {
        $project: {
          _id: 0,
          day: "$_id",
          cve_count: 1,
        },
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    // Create a complete list of days with 0 CVE count
    const dailyCVEMap = new Map(
      result.map((entry) => [entry.day, entry.cve_count])
    );
    const completeResult = Array.from({ length: daysInMonth }, (_, i) => ({
      day: i + 1,
      cve_count: dailyCVEMap.get(i + 1) || 0,
    }));

    return completeResult;
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching daily CVEs for the specified month and year");
  }
};

const getWeeklyCVEsForProduct = async (db, product) => {
  try {
    const endDate = new Date(); // Current date (today)
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - (26 * 7)); // 26 weeks ago

    const pipeline = [
      {
        $match: {
          cvss_score: { $gte: 7 }, // CVSS ≥ 7
          "cpe.product": { $ne: "n/a" }, // Exclude "n/a"
          published_at: { $gte: thirtyDaysAgo }, // Only last 30 days
        },
      },
      { $unwind: "$cpe" },
      {
        $match: {
          "cpe.product": { $ne: "n/a" },
        },
      },
      {
        $group: {
          _id: "$cpe.product",
          description: { $first: "$description" },
          cvss_score: { $max: "$cvss_score" }, // Get the highest CVSS score for that product
          cve_count: { $sum: 1 },
          latest_date: { $max: "$published_at" }, // Get the most recent publication date
        },
      },
      {
        $sort: { _id: 1 } // Sort by week number (oldest to newest)
      }
    ];

    const result = await db.collection("unified_cves").aggregate(pipeline).toArray();

    // Create a map of week numbers to CVE counts
    const weeklyCVEMap = new Map(result.map(entry => [entry._id, entry.cve_count]));

    // Generate an array with weeks numbered from 1 (most recent) to 26 (oldest)
    const completeResult = Array.from({ length: 26 }, (_, i) => ({
      week: i + 1, // Week 1 is most recent, Week 26 is oldest
      cve_count: weeklyCVEMap.get(getISOWeekNumber(endDate) - i) || 0
    }));

    return completeResult;
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching weekly CVEs for product");
  }
};

// Helper function to get the ISO week number of a date
const getISOWeekNumber = (date) => {
  const tempDate = new Date(date);
  tempDate.setHours(0, 0, 0, 0);
  tempDate.setDate(tempDate.getDate() + 4 - (tempDate.getDay() || 7));
  const yearStart = new Date(tempDate.getFullYear(), 0, 1);
  return Math.ceil((((tempDate - yearStart) / 86400000) + 1) / 7);
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



const getCriticalProducts = async (db, viewMore) => {
  try {
    const currentDate = new Date();
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(currentDate.getFullYear() - 1); // Get data from last 1 year

    const pipeline = [
      {
        $match: {
          cvss_score: { $gte: 7 }, // CVSS ≥ 7
          "cpe.product": { $ne: "n/a" }, // Exclude "n/a"
          published_at: { $gte: thirtyDaysAgo }, // Only last 30 days
        },
      },
      { $unwind: "$cpe" },
      {
        $match: {
          "cpe.product": { $ne: "n/a" },
        },
      },
      {
        $group: {
          _id: "$cpe.product",
          description: { $first: "$description" },
          cvss_score: { $max: "$cvss_score" }, // Get the highest CVSS score for that product
          cve_count: { $sum: 1 },
          latest_date: { $max: "$published_at" }, // Get the most recent publication date
        },
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
          latest_date: 1,
        },
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    if (result.length === 0) {
      return { message: "No critical products found in the past year." };
    }

    if (viewMore) {
      return {
        remaining_list: result.slice(3), // Return 4th to 30th (from index 3 onward)
        total: result.length, // Total count of available products
      };
    } else {
      return {
        top_3: result.slice(0, 3), // Return the top 3 based on the highest CVSS scores
        total: result.length, // Total count of available products
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
          "cpe.product": { $ne: "n/a" }, // Exclude "n/a" products
          published_at: { $gte: thirtyDaysAgo }, // Only data from last 30 days
        },
      },
      { $unwind: "$cpe" }, // Unwind the vulnerable_cpe array
      {
        $match: {
          "cpe.product": { $ne: "n/a" }, // Ensure no "n/a" products after unwind
        },
      },
      {
        $group: {
          _id: "$cpe.product", // Group by product name
          description: { $first: "$description" }, // Take the first available description
          cve_count: { $sum: 1 }, // Count CVEs for each product
          latest_date: { $max: "$published_at" } // Get the most recent CVE for that product
        }
      },
      { $sort: { latest_date: -1 } }, // Sort by the most recent CVE first
      { $limit: 30 }, // Get top 30 products based on the latest CVE dates
      {
        $project: {
          _id: 0,
          product: "$_id",
          description: 1,
          cve_count: 1,
          latest_date: 1, // Return the latest date along with other data
        },
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    if (result.length === 0) {
      return { message: "No recent products found in the past year." };
    }

    if (viewMore) {
      return {
        remaining_list: result.slice(3), // Return 4th to 30th (from index 3 onward)
        total: result.length, // Total count of available products
      };
    } else {
      return {
        top_3: result.slice(0, 3), // Return the top 3 most recent products
        total: result.length, // Total count of available products
      };
    }
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching recent products");
  }
};



const getTopSevereCVEs = async (db, vendor) => {
  try {
    let query = {};
    if (vendor) {
      query["cpe.vendor"] = { $regex: new RegExp(vendor, "i") }; // Filter based on vendor name
    }

    const pipeline = [
      {
        $match: query, // Apply the vendor filter
      },
      {
        $unwind: "$cpe", // Unwind the array to access individual CPEs
      },
      {
        $match: {
          "cpe.vendor": { $regex: new RegExp(vendor, "i") }, // Filter by vendor
        },
      },
      {
        $sort: { cvss_score: -1 }, // Sort by highest CVSS score first
      },
      {
        $limit: 5, // Limit to top 5 CVEs
      },
      {
        $project: {
          _id: 0,
          cve_id: 1,
          description: 1,
          cvss_score: 1, // Include CVSS score in the result
        },
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    if (result.length === 0) {
      return { message: `No severe CVEs found for the vendor: ${vendor}` };
    }

    return result; // Return the list of top 5 severe CVEs
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching CVEs for the vendor");
  }
};

const getTotalVulnerabilities = async (db) => {
  try {
    const currentDate = new Date(); // Current date

    const pipeline = [
      {
        $match: {
          published_at: { $lte: currentDate }, // Include all vulnerabilities up to the current date
        },
      },
      {
        $group: {
          _id: null,
          total_vulnerabilities: { $sum: 1 }, // Count all vulnerabilities
        },
      },
      {
        $project: {
          _id: 0,
          total_vulnerabilities: 1,
        },
      },
    ];

    const result = await db
      .collection("unified_cves")
      .aggregate(pipeline)
      .toArray();

    return result.length > 0 ? result[0] : { total_vulnerabilities: 0 };
  } catch (error) {
    console.error(error);
    throw new Error("Error fetching total vulnerabilities");
  }
};

const processProductsBoxDataStats = async (db) => {
    const [
      topProduct,
      topProductFixes,
      avgProductCVEs,
      totalProducts,
      highRiskProducts,
    ] = await Promise.all([
      getProductWithMostCVEs(db),
      getTopProductByFixes(db),
      getAverageProductCVEsPerYear(db),
      getTotalProducts(db),
      getHighRiskProductCount(db),
    ]);

    const result = {
      top_product: topProduct,
      top_product_fixes: topProductFixes,
      average_product_cves_per_year: avgProductCVEs,
      total_products: totalProducts,
      high_risk_products: highRiskProducts,
    };

  // console.log(result);

  return result;

}

const updateProductsBoxDataStats = async (db) => {
  const boxDataCollection = createBoxDataModel(db);

  logger.info("udpating Box data for products");
  const result = await processProductsBoxDataStats(db);

  const status = await boxDataCollection.updateOne(
    {_id: "products"},
      {$set: {data: result, updated_at: new Date() } },
    { upsert: true }
  );

  const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
  logger.info(msg);
}

const getProductsBoxDataStats = async (db) => {
  const boxDataCollection = createBoxDataModel(db);

  logger.info("checking cached collection for products BoxData");
  const result = await boxDataCollection.findOne({ _id: "products" });

  if (result) {
    logger.info("returning Cached Boxdata for products BoxData");
    return result.data;
  }

  // Process if cached data is not found
  logger.info("processing Boxdata for products");
  return await processProductsBoxDataStats(db);
};

const processVendorsBoxDataStats = async (db) => {
    const currentYear = new Date().getFullYear();

    const [topVendor, topVendorFixes, avgCVE, highRiskVendors, totalVendors] =
      await Promise.all([
        getTopVendorByYear(db),
        getTopVendorByFixes(db, currentYear),
        getAverageCVEsPerYear(db),
        getHighRiskVendorCount(db),
        getTotalVendors(db),
      ]);

  const result = [
      {
        "Top Vendor": {
          Value: topVendor._id,
          Count: topVendor.count,
        },
      },
      {
        "Top Vendor By Fixes": {
          Value: topVendorFixes._id,
          Count: topVendorFixes.count,
        },
      },
      {
        "Average Cves Per Year": {
          Value: avgCVE._id || null,
          Count: avgCVE.count || null,
        },
      },
      {
        "High Risk Vendors": {
          Value: highRiskVendors._id || null,
          Count: highRiskVendors.count || null,
        },
      },
      {
        "Total Vendors": {
          Value: totalVendors._id,
          Count: totalVendors.count,
        },
      },
    ];

  return result;

}

const updateVendorsBoxDataStats = async (db) => {
  const boxDataCollection = createBoxDataModel(db);

  logger.info("udpating Box data for vendors");
  const result = await processVendorsBoxDataStats(db);

  const status = await boxDataCollection.updateOne(
    {_id: "vendors"},
      {$set: {data: result, updated_at: new Date() } },
    { upsert: true }
  );

  const msg = `acknowledgement of the udpate: ${status?.acknowledged}`;
  logger.info(msg);
}

const getVendorsBoxDataStats = async (db) => {
  const boxDataCollection = createBoxDataModel(db);
   
  logger.info("checking cached collection ");
  const result = await boxDataCollection.findOne({_id: "vendors"});

  if ( result ){
    logger.info("returning Cached Boxdata for vendors BoxData");
    return result.data;
  }

  // process if cached not found
  logger.info("processing Boxdata for vendors");
  return await processVendorsBoxDataStats(db);
}

const { ObjectId } = require("mongodb");

const getMatchedVendorsAndProducts = async (db) => {
  const auditDoc = await db.collection("audit_cves").findOne({ _id: ObjectId("4ccd88058905") });
  if (!auditDoc) return [];

  const unifiedDocs = await db.collection("unified_cves").find({}).toArray();

  const unifiedVendors = new Set();
  const unifiedProducts = new Set();

  // Collect all vendors and products from unified_cves
  unifiedDocs.forEach(doc => {
    if (Array.isArray(doc.cpe)) {
      doc.cpe.forEach(cpeEntry => {
        if (cpeEntry.vendor && typeof cpeEntry.vendor === "string")
          unifiedVendors.add(cpeEntry.vendor.toLowerCase());

        if (cpeEntry.product && typeof cpeEntry.product === "string")
          unifiedProducts.add(cpeEntry.product.toLowerCase());
      });
    }
  });

  const results = new Set(); // To avoid duplicates

  const isValidString = str => {
    return typeof str === "string" && str.length > 2 && isNaN(str);
  };

  const softwareName = auditDoc?.Name?.toLowerCase() || "";
  const publisherName = auditDoc?.Publisher?.toLowerCase() || "";

  const softwareWords = softwareName.split(/[\s\-_.]+/).filter(isValidString);
  const publisherWords = publisherName.split(/[\s\-_.]+/).filter(isValidString);
  const fullPhrases = [softwareName, publisherName];

  // Match against vendors
  unifiedVendors.forEach(vendor => {
    if (
      fullPhrases.includes(vendor) ||
      softwareWords.includes(vendor) ||
      publisherWords.includes(vendor) ||
      fullPhrases.some(phrase => phrase.includes(vendor))
    ) {
      results.add(vendor);
    }
  });

  // Match against products
  unifiedProducts.forEach(product => {
    if (
      fullPhrases.includes(product) ||
      softwareWords.includes(product) ||
      publisherWords.includes(product) ||
      fullPhrases.some(phrase => phrase.includes(product))
    ) {
      results.add(product);
    }
  });

  return Array.from(results);
};




module.exports = {
  filterByCVEId,
  getMatchedVendorsAndProducts,
  generalSearch,
  getCveStatisticsByVendor,
  getCvesByVendorAndYear,
  getCvssScoreRanges,
  getProductVersions,
  getProductVersionVulnerabilities,
  getVersionDetails,
  getFilteredProductVulnerabilities,
  getFilteredVendorVulnerabilities,
  getUniqueVendors,
  getUniqueProducts,
  vendorExistsInCVE,
  productExistsInCVE,
  checkVendor,
  getAlphabeticalVendors,
  getAlphabeticalProducts,
  getTopProductStats,
  getAttackVectorStats,
  getBoxDataStats,
  getCWEStatsFast,
  getCvssScoreRangesFast,
  getTopVendorStats,
  getTopVendorByYear,
  getTopVendorByFixes,
  getAverageCVEsPerYear,
  getHighRiskVendorCount,
  getTotalVendors,
  getTopProductByFixes,
  getProductWithMostCVEs,
  getHighRiskProductCount,
  getAverageProductCVEsPerYear,
  getTotalProducts,
  getFilteredCves,
  getFeed,
  getDailyCVEsForProductVersion,
  getCriticalProducts,
  getRecentProducts,
  getTopSevereCVEs,
  getTotalVulnerabilities,
  updateBoxDataStats,
  getProductsBoxDataStats,
  updateProductsBoxDataStats,
  getVendorsBoxDataStats,
  updateVendorsBoxDataStats,
  getCWEStats,
  updateCWEStats,
  getCvssScoreRanges,
  updateCvssScoreRanges,
  getExploitedStats,
  updateExploitedStats,

  getFixesStats,
  updateFixesStats,
  getTopVendorStats,
  updateTopVendorStats,
  getCVEStats,
  updateCVEStats,
  generalSearchProductVersion,
getTopProductByFixes,
};
