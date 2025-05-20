const { createWatchlistModel, createWatchlistLogsModel } = require("../models/watchlist");
const { createUnifiedModel } = require("../models/CVE");
const { sendAction } = require("../services/watchlistService");
const logger = require("../logger");

const createResolutionStatusModel = (db) => {
  return db.collection("resolution_status");
};

const createResolutionLogModel = (db) => {
  return db.collection("resolution_logs");
};

const {
  // vendorExistsInCVEFast,
  vendorExistsInCVE,
  productExistsInCVE,
  getCVECount,
  getFixesStats,
  getProductVersions,
} = require("./cveController"); // Ensure this function checks if vendor exists

const MAX_ITEMS_PER_WATCHLIST = 10; // Set maximum limit per watchlist

const addItemToWatchlist = async (db, username, watchlistName, item) => {
  const watchlistCollection = createWatchlistModel(db);
  const actionLogCollection = createWatchlistLogsModel(db);

  // Separate logic for checking vendors and products in other watchlists
  const query = {
    username,
    "watchlists.items": {
      $elemMatch: item.vendor
        ? { vendor: item.vendor }
        : { product: item.product },
    },
  };

  const existingItem = await watchlistCollection.findOne(query);

  // Allow Apple as a Vendor and Apple as a Product separately
  if (existingItem) {
    if (
      (item.vendor &&
        existingItem.watchlists.some((wl) =>
          wl.items.some((i) => i.vendor === item.vendor)
        )) ||
      (item.product &&
        existingItem.watchlists.some((wl) =>
          wl.items.some((i) => i.product === item.product)
        ))
    ) {
      throw new Error(
        `Item "${
          item.vendor || item.product
        }" is already present in another watchlist.`
      );
    }
  }

  // Find the specific watchlist for the user
  const existingWatchlist = await watchlistCollection.findOne(
    { username, "watchlists.name": watchlistName },
    { projection: { "watchlists.$": 1 } }
  );

  // console.log(existingWatchlist);
  if (existingWatchlist && existingWatchlist.watchlists.length > 0) {
    const currentItems = existingWatchlist.watchlists[0].items;

    // Check if the current number of items exceeds the threshold
    if (currentItems.length >= MAX_ITEMS_PER_WATCHLIST) {
      throw new Error(
        `Cannot add item. The watchlist "${watchlistName}" already has ${MAX_ITEMS_PER_WATCHLIST} items.`
      );
    }
  } else {
    throw new Error(`Watchlist "${watchlistName}" not found.`);
  }

  // Create a new watchlist entry for the user
  logger.debug("updating collection");
  // Perform the update to add the item to the specified watchlist
  const result = await watchlistCollection.findOneAndUpdate(
    { username, "watchlists.name": watchlistName },
    { 
      $addToSet: { "watchlists.$.items": item }, 
    }, // Use $addToSet to avoid duplicates
    { returnDocument: "after" }
  );

  if (result) {
    const key = Object.keys(item)[0];
    const val = item[key];
    const msg = `${key} ${val} added to watchlist "${watchlistName}" successfully.`;
    // Log the action
    await actionLogCollection.insertOne({
      username,
      action: "ADD",
      item: {type: key, value: val},
      watchlistName,
      timestamp: new Date(),
      message: msg,
    });
    sendAction(db, username, msg);
    return {
      message: `Item added to watchlist "${watchlistName}" successfully.`,
    };
  } else {
    throw new Error(`Failed to add item to watchlist "${watchlistName}".`);
  }
};

const addVendorToWatchlist = async (
  db,
  username,
  watchlistName,
  vendorName
) => {
  const watchlistCollection = createWatchlistModel(db);
  const vendorObject = {
    vendor: vendorName,
  };

  // Ensure the vendor exists in CVE records
  const vendorExists = await db
    .collection("unified_cves")
    .findOne({ "cpe.vendor": vendorName });
  if (!vendorExists) {
    throw new Error(
      `Vendor "${vendorName}" does not exist in the CVE records.`
    );
  }

  const msg = await addItemToWatchlist(
    db,
    username,
    watchlistName,
    vendorObject
  );

  return msg;
};

const addProductToWatchlist = async (
  db,
  username,
  watchlistName,
  productName,
) => {
  const watchlistCollection = createWatchlistModel(db);
  const productObject = {
    product: productName,
  };

  // Ensure the product exists in CVE records
  const productExists = await db
    .collection("unified_cves")
    .findOne({ "cpe.product": productName });
  if (!productExists) {
    return {
      message: `Product '${productName}' does not exist in CVE records.`,
      success: false,
    };
  }

  const msg = await addItemToWatchlist(
    db,
    username,
    watchlistName,
    productObject,
  );

  // Sync the watchlist products with resolutions after adding new product
  await syncWatchlistWithResolutions(db, username);

  return msg;
};

const removeItemFromWatchlist = async (db, username, watchlistName, item) => {
  const watchlistCollection = createWatchlistModel(db);
  const actionLogCollection = createWatchlistLogsModel(db);

  logger.info(username);
  logger.info(watchlistName);
  // console.log(item);
  // Perform the update to remove the item from the specified watchlist
  const result = await watchlistCollection.findOneAndUpdate(
    { username, "watchlists.name": watchlistName },
    { $pull: { "watchlists.$.items": item } }, // Use $pull to remove the item
    { returnDocument: "after" }
  );

  if (result) {
    const key = Object.keys(item)[0];
    const val = item[key];

    const msg = `${key} ${val} removed from watchlist "${watchlistName}" successfully.`;
    await actionLogCollection.insertOne({
      username,
      action: "REMOVE",
      item: {type: key, value: val},
      watchlistName,
      timestamp: new Date(),
      message: msg,
    });
    sendAction(db, username, msg);
    await syncWatchlistWithResolutions(db, username);

    return {
      message: `Item removed from watchlist "${watchlistName}" successfully.`,
    };
  } else {
    throw new Error(`Watchlist "${watchlistName}" not found.`);
  }
};

// Fetch the user's watchlist
const getWatchlist = async (db, username) => {
  const watchlistCollection = createWatchlistModel(db);
  return await watchlistCollection.findOne({ username });
};

const getCvesByVendorsAndProducts = async (
  db,
  username,
  page = 1,
  limit = 10,
  selectedWatchlist = null,
  selectedFilter = null
) => {
  const unifiedCollection = createUnifiedModel(db);
  const skip = (page - 1) * limit;

  // Get user's watchlist
  const watch = await getWatchlist(db, username);
  if (!watch) {
    return {
      success: false,
      message: "Watchlist not found",
      data: [],
      pagination: { page, limit, total_items: 0, pages: 0 },
    };
  }

  // Find the selected watchlist
  const watchlist = watch.watchlists.find(
    (wl) => wl.name === selectedWatchlist
  );
  if (!watchlist) {
    return {
      success: false,
      message: "Selected watchlist not found",
      data: [],
      pagination: { page, limit, total_items: 0, pages: 0 },
    };
  }

  // Build filters array: if a filter is selected, use it; otherwise use all watchlist items
  let filters = [];
  if (selectedFilter) {
    // Single filter selected
    filters = watchlist.items.filter((item) => {
      const value = item.vendor || item.product;
      return value === selectedFilter;
    });
  } else {
    // Use all watchlist items
    filters = watchlist.items;
  }

  if (filters.length === 0) {
    return {
      success: true,
      data: [],
      pagination: { page, limit, total_items: 0, pages: 0 },
    };
  }

  // Create match criteria: match if vendor OR product matches any filter string
  const vendorFilters = filters
    .filter((f) => f.vendor)
    .map((f) => ({ "cpe.vendor": f.vendor }));
  const productFilters = filters
    .filter((f) => f.product)
    .map((f) => ({ "cpe.product": f.product }));

  const matchCriteria = {
    $or: [...vendorFilters, ...productFilters],
  };

  // Get total items - use countDocuments with an index-supported query
  const total_items = await unifiedCollection.countDocuments(matchCriteria);

  // Use a proper projection to only fetch the needed fields
  // and take advantage of indexes
  const cves = await unifiedCollection
    .find(matchCriteria)
    .sort({ published_at: -1 })
    .skip(skip)
    .limit(limit)
    .project({
      _id: 0,
      cve_id: 1,
      description: 1,
      cvss_score: 1,
      epss_score: "$epss.score",
      published_at: 1,
      updated_at: 1,
      source: 1,
    })
    .toArray();

  return {
    success: true,
    data: cves,
    pagination: {
      page,
      limit,
      total_items,
      pages: Math.ceil(total_items / limit),
    },
  };
};

const removeVendorFromWatchlist = async (
  db,
  username,
  watchlistName,
  vendorName
) => {
  const watchlistCollection = createWatchlistModel(db);

  const vendorObject = {
    vendor: vendorName,
  };

  return await removeItemFromWatchlist(
    db,
    username,
    watchlistName,
    vendorObject
  );
};

const removeProductFromWatchlist = async (
  db,
  username,
  watchlistName,
  productName
) => {
  const watchlistCollection = createWatchlistModel(db);

  const productObject = {
    product: productName,
  };

  return await removeItemFromWatchlist(
    db,
    username,
    watchlistName,
    productObject
  );
};

const updateWatchlistNames = async (db, user) => {
  const watchlistCollection = createWatchlistModel(db);

  // Fetch the existing watchlists for the user
  const existingUser = await watchlistCollection.findOne({ username: user });

  if (existingUser && existingUser.watchlists) {
    const watchlists = existingUser.watchlists;

    // Create a mapping of watchlist names to their indices
    const watchlistMap = {};
    let index = 1;
    watchlists.forEach((wl) => {
      
      // const match = wl.name.match(/watchlist\s*(\d+)/i);
      // if (match) {
        watchlistMap[index] = wl;
        index++;
      // }
    });

    // Determine the next available index for the new watchlist
    let nextIndex = 1;
    while (watchlistMap[nextIndex]) {
      nextIndex++;
    }

    // Update existing watchlists to have sequential names
    const updatedWatchlists = watchlists.map((wl) => {
      // const match = wl.name.match(/watchlist\s*(\d+)/i);
      // if (match) {
        // const index = parseInt(match[1], 10);
        return { ...wl, name: wl.name };
      // }
      // return wl;
    });

    // Return the updated watchlists and the next index
    return { updatedWatchlists, nextIndex };
  }

  // If no existing watchlists, return an empty array and start from index 1
  return { updatedWatchlists: [], nextIndex: 1 };
};
const renameWatchlist = async (db, user, watchlistName, newWatchlistName) => {
  const watchlistCollection = createWatchlistModel(db);

  // Perform the update in the database
  await watchlistCollection.findOneAndUpdate(
    { username: user, "watchlists.name": watchlistName },
    { $set: { "watchlists.$.name": newWatchlistName } }, // Update the watchlists array
  );

  return { message: `Renamed "${watchlistName} to "${newWatchlistName}".` };
};

const createWatchlist = async (db, user, watchlistName) => {
  const watchlistCollection = createWatchlistModel(db);

  // Update existing watchlists and get the next index
  const { updatedWatchlists, nextIndex } = await updateWatchlistNames(db, user);

  // Add the new watchlist with the next available index
  const newWatchlist = { name: watchlistName , items: [] };
  // console.log("new:", newWatchlist);
  // console.log("old:", updatedWatchlists);
  updatedWatchlists.push(newWatchlist);

  // Perform the update in the database
  await watchlistCollection.findOneAndUpdate(
    { username: user },
    { $set: { watchlists: updatedWatchlists } }, // Update the watchlists array
    { returnDocument: "after", upsert: true }
  );

  return { message: `New watchlist "${newWatchlist.name}" created.` };
};

const removeWatchlist = async (db, user, watchlistName) => {
  const watchlistCollection = createWatchlistModel(db);

  logger.info(user);
  logger.info(watchlistName);
  // Perform the update to remove the specified watchlist
  const result = await watchlistCollection.findOneAndUpdate(
    { username: user },
    { $pull: { watchlists: { name: watchlistName } } }, // Use $pull to remove the watchlist
    { returnDocument: "after" }
  );

  // console.log(result);

  if (result) {
    await updateWatchlistNames(db, user); // Call the function to re-index watchlists
    return { message: `Watchlist "${watchlistName}" removed successfully.` };
  } else {
    throw new Error(`Watchlist "${watchlistName}" not found.`);
  }
};

const getUserWatchlistProducts = async (req, res) => {
  try {
    logger.info(`GET: /watchlist/products`);

    const db = await connectDB();
    const authHeader = req.headers.authorization;
    const username = await getUsername(db, authHeader);

    // Fetch user's watchlist from the database
    const userWatchlist = await db.collection("watchlist").findOne({ username });

    if (!userWatchlist || !userWatchlist.watchlists || userWatchlist.watchlists.length === 0) {
      return res.json({
        username,
        message: "No products in the watchlist.",
        products: []
      });
    }

    // Extract product names from all watchlists
    const products = userWatchlist.watchlists.flatMap(watchlist =>
      watchlist.items
        .filter(item => item.product) // Extract only product names
        .map(item => item.product)
    );

    if (products.length === 0) {
      return res.json({
        username,
        message: "No products in the watchlist.",
        products: []
      });
    }

    // Return product names
    res.json({
      username,
      products
    });

  } catch (err) {
    logger.error(err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
};

// will get from the pre computed stats
// Implement this function agar pre computed nahi hua toh manually bhi ho jaye!
const getWatchlistCVEStats = async (db, username) => {
  const watchlistCollection = db.collection("watchlist");
  const statsCollection = db.collection("watchlist_stats");
  const cveCollection = db.collection("unified_cves");

  // Fetch user's watchlists
  const userWatchlist = await watchlistCollection.findOne({ username });

  if (!userWatchlist || !userWatchlist.watchlists.length) {
    return { message: "No watchlists found for user." };
  }

  const watchlistItems = [];
  userWatchlist.watchlists.forEach((watchlist) => {
    watchlist.items.forEach((item) => {
      if (item.vendor)
        watchlistItems.push({ name: item.vendor, type: "Vendor" });
      if (item.product)
        watchlistItems.push({ name: item.product, type: "Product" });
    });
  });

  if (!watchlistItems.length) {
    return { message: "No vendors or products found in any watchlist" };
  }

  const watchlistStats = [];

  for (const item of watchlistItems) {
    let stats = await statsCollection.findOne({ _id: item.name });

    if (!stats) {
      // If precomputed stats are missing, fetch manually
      const filter =
        item.type === "Vendor"
          ? { "cpe.vendor": item.name }
          : { "cpe.product": item.name };

      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

      const currentDate = new Date();
      const startOfThisMonth = new Date(
        currentDate.getFullYear(),
        currentDate.getMonth(),
        1
      );
      const startOfLastMonth = new Date(
        currentDate.getFullYear(),
        currentDate.getMonth() - 1,
        1
      );

      const totalCVE = await cveCollection.countDocuments(filter);
      const cveAddedThisWeek = await cveCollection.countDocuments({
        ...filter,
        published_at: { $gte: oneWeekAgo },
      });
      const patchesAvailable = await cveCollection.countDocuments({
        ...filter,
        patch_url: { $ne: [] },
      });

      const lastMonthCount = await cveCollection.countDocuments({
        ...filter,
        published_at: { $gte: startOfLastMonth, $lt: startOfThisMonth },
      });

      const thisMonthCount = await cveCollection.countDocuments({
        ...filter,
        published_at: { $gte: startOfThisMonth },
      });

      let trend = "Constant";
      if (thisMonthCount > lastMonthCount) {
        trend = "Rising";
      } else if (thisMonthCount < lastMonthCount) {
        trend = "Dropping";
      }

      stats = {
        _id: item.name,
        type: item.type,
        cveAddedThisWeek,
        totalCVE,
        patchesAvailable,
        lastMonthCount,
        thisMonthCount,
        trend,
        lastUpdated: new Date(),
      };

      // Store manually fetched data for future use
      await statsCollection.updateOne(
        { _id: item.name },
        { $set: stats },
        { upsert: true }
      );
    }

    watchlistStats.push(stats);
  }

  return watchlistStats.length > 0
    ? watchlistStats
    : { message: "No stats available." };
};

// pre computed watchlist stats
const computeWatchlistStats = async (db) => {
  const watchlistCollection = db.collection("watchlist");
  const cveCollection = db.collection("unified_cves");
  const statsCollection = db.collection("watchlist_stats");

  const allWatchlists = await watchlistCollection.find({}).toArray();
  if (!allWatchlists.length) return { message: "No watchlists found." };

  // Get the date range for "this week"
  const oneWeekAgo = new Date();
  oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

  const currentDate = new Date();
  const startOfThisMonth = new Date(
    currentDate.getFullYear(),
    currentDate.getMonth(),
    1
  );
  const startOfLastMonth = new Date(
    currentDate.getFullYear(),
    currentDate.getMonth() - 1,
    1
  );

  const stats = {};

  for (const userWatchlist of allWatchlists) {
    for (const watchlist of userWatchlist.watchlists) {
      for (const item of watchlist.items) {
        const key = item.vendor || item.product;
        const type = item.vendor ? "Vendor" : "Product";

        if (!stats[key]) {
          const filter = item.vendor
            ? { "cpe.vendor": item.vendor }
            : { "cpe.product": item.product };

          // Fetch total CVEs
          const totalCVE = await unifiedCollection.countDocuments(filter);

          // Fetch CVEs added this week
          const cveAddedThisWeek = await unifiedCollection.countDocuments({
            ...filter,
            published_at: { $gte: oneWeekAgo },
          });

          // Fetch available patches
          const patchesAvailable = await unifiedCollection.countDocuments({
            ...filter,
            patch_url: { $exists: true, $ne: [] },
          });

          // Trend calculation (percentage movement)
          const lastMonthCount = await cveCollection.countDocuments({
            ...filter,
            published_at: { $gte: startOfLastMonth, $lt: startOfThisMonth },
          });

          const thisMonthCount = await cveCollection.countDocuments({
            ...filter,
            published_at: { $gte: startOfThisMonth },
          });

          let trend = "Constant";
          if (thisMonthCount > lastMonthCount) {
            trend = "Rising";
          } else if (thisMonthCount < lastMonthCount) {
            trend = "Dropping";
          }

          stats[key] = {
            _id: key,
            type,
            cveAddedThisWeek,
            totalCVE,
            patchesAvailable,
            lastMonthCount,
            thisMonthCount,
            trend,
            lastUpdated: new Date(),
          };
        }
      }
    }
  }
};

// watchlistController.js

const getAllCvesByVendorsAndProducts = async (
  db,
  username,
  selectedWatchlist = null,
  selectedFilters = [],
  status = "open",
  page = 1,
  limit = 10,
  sortByCVSS = "default",
  year=null,
  month=null,
) => {
  try {
    const unifiedCollection = createUnifiedModel(db);
    const skip = (page - 1) * limit;

    // Get user's watchlist
    const watch = await getWatchlist(db, username);
    if (!watch || !watch.watchlists.length) {
      return { cves: [], totalPages: 0 };
    }

    // Find the selected watchlist
    const watchlist =
      watch.watchlists.find((wl) => wl.name === selectedWatchlist) ||
      watch.watchlists[0]; // Default to first watchlist if not found

    
    if (!watchlist || !watchlist.items || !watchlist.items.length) {
      return { cves: [], totalPages: 0 };
    }

    // $match values
    let matchCriteria = {};

    //resolution collection for feed
    const resolutionStatusCollection = createResolutionStatusModel(db)

    //Id's from resolution collection
    const cve_ids = await resolutionStatusCollection.aggregate([
      {
        $match: { 
          username,
        }
      },
      {
        $project: {
          "cves": {
            $filter: {
              input: "$cves",
              as: "cve",
              cond: { 
                $eq: ["$$cve.status", status ]
              }
            }
          }
        }
      },
      {
        $project: {
          cves: "$cves.cve_id"
        }
      }
    ]).toArray();


    if( cve_ids[0] && cve_ids[0].cves ){
      matchCriteria["_id"] = { "$in": cve_ids[0]?.cves };
    } else {
      matchCriteria["_id"] = { "$in": [] };
    }

    // Build filters array based on selection
    let filteredItems;

    if (selectedFilters && selectedFilters.length > 0) {
      // Only use items that match the selected filters
      filteredItems = watchlist.items.filter((item) => {
        if( item.product ){
          const itemValue = item.product;
          return selectedFilters.includes(itemValue);
        }
      });

    const productFilters = filteredItems
      .filter((f) => f.product)
      .map((f) => ({ "cpe.product": f.product }));

      matchCriteria["$or"] = [...productFilters];


      // console.log("Using filtered items:", filteredItems.length);
    } else {
      // Use all items in the watchlist if no filters are selected
      filteredItems = watchlist.items.filter((item) => {
        if( item.product ){
          const itemValue = item.product;
          return itemValue;
        }
      });

      // console.log("Using all items:", filteredItems.length);
    }


    if (selectedFilters.length === 0 && status === 'open' && filteredItems.length === 0) {
      return { cves: [], totalPages: 0 };
    }
    // Create MongoDB query criteria
    //const vendorFilters = filteredItems
    //  .filter((f) => f.vendor)
    //  .map((f) => ({ "cpe.vendor": f.vendor }));


    // console.log("MongoDB query criteria:", JSON.stringify(matchCriteria));


    // year filters
    if (year && month ){ 
      const startDate = new Date(
        `${year}-${month}-01T00:00:00.000Z`
      );
      const endDate = new Date(startDate);
      endDate.setMonth(startDate.getMonth() + 1);
      match.published_at = {
        $gte: startDate,
        $lt: endDate,
      };

    } else if (year){
      matchCriteria["published_at"] = {
        $gte: new Date(`${year}-01-01`),
        $lt: new Date(`${parseInt(year) + 1}-01-01`),
      };

    } else if (month) {
      const currentYear = new Date().getFullYear();

      const startDate = new Date(
        `${currentYear}-${month}-01T00:00:00.000Z`
      );

      const endDate = new Date(startDate);
      endDate.setMonth(startDate.getMonth() + 1);

      matchCriteria["published_at"] = {
        $gte: startDate,
        $lt: endDate,
      };
    }

  // console.log("matchCriteria", matchCriteria);

    let sortField = {}; // default sort

    if (sortByCVSS === "lowest-scores-first" ) {
      sortField['cvss_score'] = 1
      logger.info("sortByCVSS low provided ");
      // console.log(sortField);
    } else if (sortByCVSS === "highest-scores-first" ) {
      sortField['cvss_score'] = -1
      logger.info("sortByCVSS high provided ");
      // console.log(sortField);
    } else {
      logger.info("Invalid sortByCVSS field provided ");
      // console.log(sortField);
    }

    sortField['published_at'] = -1;


    // console.log("sortField", sortField);

    // Execute query with pagination
    const total = await unifiedCollection
      .countDocuments(matchCriteria);

    // console.log(`Found ${total} matching documents`);

    const cves = await unifiedCollection
      .find(matchCriteria)
      .sort(sortField)
      .skip(skip)
      .limit(limit)
      .toArray();

    // console.log(`Returning ${cves.length} CVEs for page ${page}`);

    const totalPages = Math.ceil(total / limit);

    return { cves, totalPages };
  } catch (error) {
    // console.error("Error in getAllCvesByVendorsAndProducts:", error);
    throw error;
  }
};

const getAllProductCvesCombined = async (
  db,
  username,
  page = 1,
  limit = 10
) => {
  try {
    // First sync to make sure all product CVEs are in the resolution status
    await syncWatchlistWithResolutions(db, username);

    // Get user's resolution status document
    const statusCollection = createResolutionStatusModel(db);
    const userDoc = await statusCollection.findOne({ username });

    // If no document or no CVEs, return empty
    if (!userDoc || !userDoc.cves || userDoc.cves.length === 0) {
      return { cves: [], totalPages: 0 };
    }

    // Calculate pagination
    const skip = (page - 1) * limit;
    const totalItems = userDoc.cves.length;
    const totalPages = Math.ceil(totalItems / limit);

    // Get the CVE IDs for the current page
    const pagedCveIds = userDoc.cves
      .slice(skip, skip + limit)
      .map((cve) => cve.cve_id);

    if (pagedCveIds.length === 0) {
      return { cves: [], totalPages };
    }

    // Fetch the full CVE details from unified collection
    const unifiedCollection = createUnifiedModel(db);
    const cves = await unifiedCollection
      .find({ cve_id: { $in: pagedCveIds } })
      .toArray();

    // Create a map of cve_id to status information for quick lookup
    const cveStatusMap = {};
    userDoc.cves.forEach((cve) => {
      cveStatusMap[cve.cve_id] = {
        status: cve.status,
        updated_at: cve.updated_at,
      };
    });

    // Add status to each CVE
    const cvesWithStatus = cves.map((cve) => ({
      ...cve,
      resolution_status: cveStatusMap[cve.cve_id]?.status || "open",
      resolution_updated_at: cveStatusMap[cve.cve_id]?.updated_at,
    }));

    return { cves: cvesWithStatus, totalPages };
  } catch (error) {
    logger.error("Error in getAllProductCvesCombined:", error);
    throw error;
  }
};

const updateCveStatuses = async (db, username, cveIds, status) => {
  try {
    const statusCollection = createResolutionStatusModel(db);
    const logCollection = createResolutionLogModel(db);
    const now = new Date();

    // Get user's document to find previous statuses for logging
    const userDoc = await statusCollection.findOne({ username });

    // Create a map of previous statuses
    const prevStatuses = {};
    if (userDoc && userDoc.cves) {
      userDoc.cves.forEach((cve) => {
        if (cveIds.includes(cve.cve_id)) {
          prevStatuses[cve.cve_id] = cve.status;
        }
      });
    }

    // Prepare logs
    const newLogs = cveIds.map((cveId) => ({
      cve_id: cveId,
      action: `Status changed to ${status}`,
      previous_status: prevStatuses[cveId] || "none",
      new_status: status,
      timestamp: now,
    }));

    // Update logs in a single operation
    await logCollection.updateOne(
      { username },
      {
        $push: { logs: { $each: newLogs } },
        $set: { last_updated: now },
      },
      { upsert: true }
    );

    let modified = 0;
    let upserted = 0;

    if (!userDoc) {
      // If user doesn't have a document yet, create one with all CVEs
      const cves = cveIds.map((cveId) => ({
        cve_id: cveId,
        status,
        updated_at: now,
      }));

      await statusCollection.insertOne({
        username,
        cves,
        last_updated: now,
      });

      upserted = cveIds.length;
    } else {
      // Update existing document
      for (const cveId of cveIds) {
        // Check if the CVE already exists in the array
        const cveIndex = userDoc.cves
          ? userDoc.cves.findIndex((c) => c.cve_id === cveId)
          : -1;

        if (cveIndex >= 0) {
          // Update existing CVE status
          await statusCollection.updateOne(
            { username, "cves.cve_id": cveId },
            {
              $set: {
                "cves.$.status": status,
                "cves.$.updated_at": now,
                last_updated: now,
              },
            }
          );
          modified++;
        } else {
          // Add new CVE to the array
          await statusCollection.updateOne(
            { username },
            {
              $push: {
                cves: {
                  cve_id: cveId,
                  status,
                  updated_at: now,
                },
              },
              $set: { last_updated: now },
            }
          );
          upserted++;
        }
      }
    }

    return {
      success: true,
      modified,
      upserted,
      cve_ids: cveIds,
      status,
    };
  } catch (error) {
    logger.error("Error updating CVE statuses:", error);
    throw error;
  }
};

const getUserCveStatuses = async (db, username) => {
  try {
    const statusCollection = createResolutionStatusModel(db);

    // Get user's document
    const userDoc = await statusCollection.findOne({ username });

    // If no document exists yet, return empty array
    if (!userDoc || !userDoc.cves) {
      return [];
    }

    // Format the data for the frontend (flatten the structure)
    return userDoc.cves.map((cve) => ({
      cve_id: cve.cve_id,
      status: cve.status,
      updated_at: cve.updated_at,
    }));
  } catch (error) {
    logger.error("Error fetching user CVE statuses:", error);
    throw error;
  }
};

const syncWatchlistWithResolutions = async (db, username) => {
  try {
    logger.info(
      `Syncing watchlist CVEs with resolutions for user: ${username}`
    );

    // Get user's watchlist
    const watchlistCollection = createWatchlistModel(db);
    const userWatchlist = await watchlistCollection.findOne({ username });

    if (
      !userWatchlist ||
      !userWatchlist.watchlists ||
      userWatchlist.watchlists.length === 0
    ) {
      logger.info(`No watchlists found for user: ${username}`);
      return { added: 0 };
    }

    // Extract all products from all watchlists
    const allProducts = [];
    userWatchlist.watchlists.forEach((watchlist) => {
      watchlist.items.forEach((item) => {
        if (item.product) {
          allProducts.push(item.product.trim());
        }
      });
    });

    // Remove duplicates
    const uniqueProducts = [...new Set(allProducts)];

    if (uniqueProducts.length === 0) {
      logger.info(`No products found in watchlists for user: ${username}`);
      return { added: 0 };
    }

    // Get all CVEs related to these products
    const unifiedCollection = createUnifiedModel(db);

    // Build product filters
    const productFilters = uniqueProducts.map((product) => ({
      "cpe.product": product,
    }));

    const cves = await unifiedCollection
      .find({ $or: productFilters })
      .project({ cve_id: 1, updated_at: 1, _id: 0 })
      .toArray();

    if (cves.length === 0) {
      logger.info(
        `No CVEs found for products in user's watchlist: ${username}`
      );
      return { added: 0 };
    }

    // Get user's current resolution status document
    const statusCollection = createResolutionStatusModel(db);
      
    // Delete all the existing open CVE's
    await statusCollection.findOneAndUpdate(
      { username,  }, 
      { $pull: {cves: {status: 'open' } } }
    );
    const userDoc = await statusCollection.findOne({ username });

    let addedCount = 0;
    const now = new Date();



    const cveEntries = [];
    // console.log("uniqueProducts", uniqueProducts);
    for (const product of uniqueProducts) {

      const open_cves = await unifiedCollection
        .find({
          "cpe.product": product, 
          //"cpe.version": inputVersion, 
        }, {"cve_id": 1}).toArray();

      // console.log("open_cves", open_cves);

      open_cves.forEach((cve) => {
        cveEntries.push({
          cve_id: cve.cve_id,
          status: "open", // Default status
          updated_at: cve.updated_at || now, // Use the CVE's updated_at date if available
        });
      });

      // resolved_cves.map((cve) => {
      //   cveEntries.push({
      //     cve_id: cve.cve_id,
      //     status: "resolved", // Default status
      //     updated_at: cve.updated_at || now, // Use the CVE's updated_at date if available
      //   });
      // });

    }

    if (!userDoc) {

      await statusCollection.insertOne({
        username,
        cves: cveEntries,
        last_updated: now,
      });

      addedCount = cveEntries.length;
    } else {
      // User already has a document, find which CVEs need to be added
      const existingCveIds = userDoc.cves
        ? userDoc.cves.map((cve) => cve.cve_id)
        : [];
      const newCves = cveEntries.filter(
        (cve) => !existingCveIds.includes(cve.cve_id)
      );

      if (newCves.length > 0) {
        const newCveEntries = newCves.map((cve) => ({
          cve_id: cve.cve_id,
          status: "open", // Default status
          updated_at: cve.updated_at || now, // Use the CVE's updated_at date if available
        }));

        await statusCollection.updateOne(
          { username },
          {
            $push: { cves: { $each: newCveEntries } },
            $set: { last_updated: now },
          }
        );

        addedCount = newCves.length;
      }
    }

    logger.info(
      `Added ${addedCount} new CVEs to resolution status for user: ${username}`
    );
    return { added: addedCount };
  } catch (error) {
    logger.error(
      `Error syncing watchlist with resolutions for user ${username}:`,
      error
    );
    throw error;
  }
};

const getCvesByVendorsInMultipleWatchlists = async (
  db,
  username,
  page = 1,
  limit = 10,
  sortByCVSS = "lowest-scores-first",
  year = null,
  month = null
) => {
  const unifiedCollection = createUnifiedModel(db);
  const skip = (page - 1) * limit;

  // Get all user's watchlists
  const watch = await getWatchlist(db, username);
  if (!watch) {
    return {
      success: false,
      message: "Watchlist not found",
      data: [],
      pagination: { page, limit, total_items: 0, pages: 0 },
    };
  }

  // If user has no watchlists, return early
  if (!watch.watchlists || watch.watchlists.length === 0) {
    return {
      success: false,
      message: "At least one watchlist is required for this operation",
      data: [],
      pagination: { page, limit, total_items: 0, pages: 0 },
    };
  }

  // Collect all unique vendors from all watchlists
  const allVendors = new Set();
  
  watch.watchlists.forEach(watchlist => {
    watchlist.items.forEach(item => {
      if (item.vendor) {
        allVendors.add(item.vendor);
      }
    });
  });
  
  const vendorsToQuery = Array.from(allVendors);

  // If no vendors found, return empty results
  if (vendorsToQuery.length === 0) {
    return {
      success: true,
      message: "No vendors found in any watchlist",
      data: [],
      pagination: { page, limit, total_items: 0, pages: 0 },
    };
  }

  // Create the match criteria for vendors
  const matchCriteria = {
    "cpe.vendor": { $in: vendorsToQuery }
  };

  // Add date filtering by year and month if provided
  // Only apply filters when values are provided
  if (year !== null) {
    // For year only
    if (month === null) {
      const startDate = new Date(year, 0, 1); // January 1st
      const endDate = new Date(year, 11, 31, 23, 59, 59); // December 31st
      matchCriteria.published_at = { $gte: startDate, $lte: endDate };
    } 
    // For year and month
    else {
      const startDate = new Date(year, month - 1, 1); // Month is 0-indexed in JS
      const endDate = new Date(year, month, 0, 23, 59, 59); // Last day of month
      matchCriteria.published_at = { $gte: startDate, $lte: endDate };
    }
  } 
  // For month only (apply to current year if only month is provided)
  else if (month !== null) {
    const currentYear = new Date().getFullYear();
    const startDate = new Date(currentYear, month - 1, 1);
    const endDate = new Date(currentYear, month, 0, 23, 59, 59);
    matchCriteria.published_at = { $gte: startDate, $lte: endDate };
  }

  // Get total items
  const total_items = await unifiedCollection.countDocuments(matchCriteria);

  // Create sort object based on sortByCVSS parameter
  const sortObject = {};
  if (sortByCVSS === "highest-scores-first") {
    sortObject.cvss_score = -1;
  } else {
    sortObject.cvss_score = 1;
  }
  
  // Add secondary sort by published date (most recent first)
  sortObject.published_at = -1;

  // Fetch the CVEs with pagination
  const cves = await unifiedCollection
    .find(matchCriteria)
    .sort(sortObject)
    .skip(skip)
    .limit(limit)
    .project({
      _id: 0,
      cve_id: 1,
      description: 1,
      cvss_score: 1,
      epss_score: "$epss.epss_score",
      published_at: 1,
      updated_at: 1,
    })
    .toArray();

  // Only include filters in response if they were applied
  const appliedFilters = {};
  if (year !== null) appliedFilters.year = year;
  if (month !== null) appliedFilters.month = month;

  return {
    success: true,
    data: cves,
    vendors: vendorsToQuery,
    ...(Object.keys(appliedFilters).length > 0 && { filters: appliedFilters }),
    pagination: {
      page,
      limit,
      total_items,
      pages: Math.ceil(total_items / limit),
    },
  };
};

const getCVEsForProductVersion = async (db, product, version) => {
  const cves = await db.collection("unified_cves")
    .find({ 
      "cpe.product": product, 
      "cpe.version": version, 
    }).project({
      "_id": 0,
      "cve_id": 1,
    }).toArray();

  if (cves.length === 0 ){
  return [];
  } else {
  return cves.map(item => item.cve_id);
  }
}

const performResolutionBeforeUpdate = async (
    db, 
    username, 
    watchlistName, 
    product, 
    newVersion 
) => {

  // Get user's watchlists
  const watch = await getWatchlist(db, username);
  if (!watch) {
    return {
      success: false,
      message: "Watchlist not found",
    };
  }

  // If user has no watchlists, return early
  if (!watch.watchlists || watch.watchlists.length === 0) {
    return {
      success: false,
      message: "At least one watchlist is required for this operation",
    };
  }

  function consolidateProductVersions(data) {
    const consolidatedProductVersion = {};

    for (const watchlist of data.watchlists) {
      const productVersion = watchlist.version;
      Object.assign(consolidatedProductVersion, productVersion);
    }

    return consolidatedProductVersion;
  }

  const productVersions = consolidateProductVersions(watch);

  const oldCVEs = 
    await getCVEsForProductVersion(db, product, productVersions[product]);

  const newCVEs = 
    await getCVEsForProductVersion(db, product, newVersion);

  // all the CVEs that are present in OLD versoin but not in NEW version
  const filteredCVEs = 
    oldCVEs.filter(element => !newCVEs.includes(element));

  // console.log(filteredCVEs);
  await updateCveStatuses(db, username, filteredCVEs, 'resolved');

  return filteredCVEs;
 
}



const getFixableCves = async (db, username) => {
  try {
    // Get the collections
    const resolutionStatusCollection = db.collection('resolution_status');
    const watchlistCollection = db.collection('watchlist');
    const unifiedCvesCollection = db.collection('unified_cves');
    
    // Find the user's watchlist
    const watchlistDoc = await watchlistCollection.findOne({ username });
    
    if (!watchlistDoc || !watchlistDoc.watchlists || watchlistDoc.watchlists.length === 0) {
      return {
        success: false,
        message: "No watchlists found for the user",
        totalFixableCves: 0,
        fixableCves: [],
        fixablePercentage: 0,
        avgFixDays: 0
      };
    }
    
    // Extract unique products from all watchlists
    const allProducts = new Set();
    watchlistDoc.watchlists.forEach(watchlist => {
      watchlist.items.forEach(item => {
        if (item.product) {
          allProducts.add(item.product);
        }
      });
    });
    
    // If no products found, return early
    if (allProducts.size === 0) {
      return {
        success: false,
        message: "No products found in watchlists",
        totalFixableCves: 0,
        fixableCves: [],
        fixablePercentage: 0,
        avgFixDays: 0
      };
    }
    
    // Find open CVEs for the user
    const openCves = await resolutionStatusCollection.findOne(
      { username, 'cves.status': 'open' }
    );
    
    if (!openCves) {
      return {
        success: true,
        message: "No open CVEs found",
        totalFixableCves: 0,
        fixableCves: [],
        fixablePercentage: 0,
        avgFixDays: 0
      };
    }
    
    // Filter open CVE IDs
    const openCveIds = openCves.cves
      .filter(cve => cve.status === 'open')
      .map(cve => cve.cve_id);
    
    // console.log(`[DEBUG] Total number of open CVEs: ${openCveIds.length}`);
    
    // Find fixable CVEs (with patches or vendor advisories)
    const fixableCves = await unifiedCvesCollection.find({
      cve_id: { $in: openCveIds },
      $or: [
        { patch_url: { $exists: true, $ne: [] } },
        { vendor_advisory: { $exists: true, $ne: [] } }
      ],
      'cpe.product': { $in: Array.from(allProducts) }
    }).toArray();
    
    // If no fixable CVEs found
    if (fixableCves.length === 0) {
      return {
        success: true,
        message: "No available fixable CVEs",
        totalFixableCves: 0,
        fixableCves: [],
        fixablePercentage: 0,
        avgFixDays: 0
      };
    }
    
    // Calculate the percentage of fixable CVEs
    const fixablePercentage = (fixableCves.length / openCveIds.length) * 100;
    
    // Get detailed CVE data for open CVEs
    // Check what's actually in the unified_cves collection
    const sampleCve = await unifiedCvesCollection.findOne();
    // console.log('[DEBUG] Sample CVE structure:', JSON.stringify(sampleCve, null, 2).substring(0, 500) + '...');
    
    const allOpenCves = await unifiedCvesCollection.find({
      cve_id: { $in: openCveIds }
    }).toArray();
    
    // console.log(`[DEBUG] Retrieved ${allOpenCves.length} CVEs from database for avgFixDays calculation`);
    
    // Current date for calculating the difference
    const currentDate = new Date();
    // console.log(`[DEBUG] Current date for calculation: ${currentDate.toISOString()}`);
    
    // Calculate total days and count of valid CVEs (with published_at date)
    let totalDays = 0;
    let validCveCount = 0;
    
    // Debug array to store individual CVE data
    const cveDebugInfo = [];
    
    // Check for different date field formats
    allOpenCves.forEach(cve => {
      // Try different possible formats for published date
      let publishDate = null;
      let publishDateSource = 'none';
      
      // Check for published_at as direct Date object
      if (cve.published_at instanceof Date) {
        publishDate = cve.published_at;
        publishDateSource = 'direct_date';
      } 
      // Check for published_at.$date as string or object
      else if (cve.published_at && cve.published_at.$date) {
        publishDate = new Date(cve.published_at.$date);
        publishDateSource = 'date_object';
      } 
      // Check for published_at as string
      else if (typeof cve.published_at === 'string') {
        publishDate = new Date(cve.published_at);
        publishDateSource = 'string_date';
      }
      // Check for alternative field names
      else if (cve.publishedDate) {
        publishDate = new Date(cve.publishedDate);
        publishDateSource = 'publishedDate';
      }
      else if (cve.published) {
        publishDate = new Date(cve.published);
        publishDateSource = 'published';
      }
      
      // If we found a valid date
      if (publishDate && !isNaN(publishDate.getTime())) {
        const daysDifference = Math.floor((currentDate - publishDate) / (1000 * 60 * 60 * 24));
        
        cveDebugInfo.push({
          cve_id: cve.cve_id,
          published_date: publishDate.toISOString(),
          days_difference: daysDifference,
          source: publishDateSource
        });
        
        totalDays += daysDifference;
        validCveCount++;
      } else {
        // Log CVEs with missing publish date
        cveDebugInfo.push({
          cve_id: cve.cve_id,
          published_date: 'MISSING',
          days_difference: 'N/A',
          source: publishDateSource,
          available_fields: Object.keys(cve).join(', ').substring(0, 100)
        });
      }
    });
    
    // Log detailed information about each CVE
    // console.log('[DEBUG] Individual CVE age information:');
    // console.table(cveDebugInfo);
    
    // If no valid dates were found, try an alternative approach
    if (validCveCount === 0) {
      // console.log('[DEBUG] No valid dates found using standard fields. Testing alternative date extraction...');
      
      // Alternative approach: Checking for nested date structures or using creation date
      for (const cve of allOpenCves) {
        // console.log(`[DEBUG] Examining full structure of CVE ${cve.cve_id}:`);
        
        // Look for any field containing the word "date" or "time"
        const dateFields = Object.keys(cve).filter(key => 
          key.toLowerCase().includes('date') || 
          key.toLowerCase().includes('time') || 
          key.toLowerCase().includes('published') ||
          key.toLowerCase().includes('created')
        );
        
        if (dateFields.length > 0) {
          // console.log(`[DEBUG] Potential date fields for ${cve.cve_id}:`, dateFields);
          for (const field of dateFields) {
            // console.log(`[DEBUG] Field ${field}:`, cve[field]);
          }
        }
      }
    }
    
    // console.log(`[DEBUG] Total days across all CVEs: ${totalDays}`);
    // console.log(`[DEBUG] Valid CVE count with publish dates: ${validCveCount}`);
    
    // Calculate average days
    const avgFixDays = validCveCount > 0 ? Math.round(totalDays / validCveCount) : 0;
    
    // console.log(`[DEBUG] Final avgFixDays calculation: ${totalDays} / ${validCveCount} = ${avgFixDays}`);
    
    // Prepare response with the new field
    return {
      success: true,
      message: "Fixable CVEs retrieved successfully",
      totalFixableCves: fixableCves.length,
      fixableCves: fixableCves.map(cve => ({
        cve_id: cve.cve_id,
        description: cve.description,
        cvss_score: cve.cvss_score,
        products: cve.cpe
          .filter(c => allProducts.has(c.product))
          .map(c => c.product),
        patch_urls: cve.patch_url || [],
        vendor_advisories: cve.vendor_advisory || []
      })),
      fixablePercentage,
      avgFixDays
    };
  } catch (error) {
    console.error('[DEBUG] Error in avgFixDays calculation:', error);
    return {
      success: false,
      message: "Internal server error",
      totalFixableCves: 0,
      fixableCves: [],
      fixablePercentage: 0,
      avgFixDays: 0
    };
  }
};

const getWatchlistProductsAndVendors = async (db, username) => {
  try {
    // Make sure username is defined and valid
    if (!username || typeof username !== 'string') {
      throw new Error('Invalid username');
    }
    
    const watchlistCollection = createWatchlistModel(db);
    
    // Find the user's watchlist document
    const userWatchlist = await watchlistCollection.findOne({ username });
    
    if (!userWatchlist || !userWatchlist.watchlists || userWatchlist.watchlists.length === 0) {
      return { products: [], vendors: [] };
    }
    
    // Extract products and vendors from all watchlists
    const productsAndVendors = {
      products: [],
      vendors: []
    };
    
    userWatchlist.watchlists.forEach(watchlist => {
      // Make sure watchlist name exists
      const watchlistName = watchlist.name || 'Unnamed Watchlist';
      
      // Safely process items array
      if (Array.isArray(watchlist.items)) {
        watchlist.items.forEach(item => {
          // Check if item is properly defined and has the expected properties
          if (item && typeof item === 'object') {
            if (item.product !== undefined) {
              productsAndVendors.products.push({
                product: item.product,
                watchlistName
              });
            }
            
            if (item.vendor !== undefined) {
              productsAndVendors.vendors.push({
                vendor: item.vendor,
                watchlistName
              });
            }
          }
        });
      }
    });
    
    return productsAndVendors;
  } catch (error) {
    logger.error(`Error getting watchlist products and vendors: ${error.message}`);
    throw new Error('Failed to retrieve watchlist products and vendors');
  }
};


module.exports = {
  addVendorToWatchlist,
  getWatchlist,
  removeVendorFromWatchlist,
  removeProductFromWatchlist,
  addProductToWatchlist,
  getCvesByVendorsAndProducts,
  removeWatchlist,
  createWatchlist,
  renameWatchlist,
  getWatchlistCVEStats,
  computeWatchlistStats,
  getAllCvesByVendorsAndProducts,
  getAllProductCvesCombined,
  updateCveStatuses,
  getUserCveStatuses,
  syncWatchlistWithResolutions,
  createWatchlist,
  getUserWatchlistProducts,
  getFixableCves,
  getCvesByVendorsInMultipleWatchlists,
  getWatchlistProductsAndVendors

};
