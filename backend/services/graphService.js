const { createUnifiedModel } = require("../models/CVE");
const { 
  getBoxDataStats,
} = require("../controllers/cveController");// controllers
const logger = require("../logger");

const transformCWEStats = async (db, vendor) => {
    const unifiedCollection = createUnifiedModel(db);

    let id = 'home-weakness';

    let match = {
        published_at: {
            $gte: new Date("2014-01-01T00:00:00Z"),
            $lt: new Date(),
        },
    };

    if (vendor !== undefined && vendor != null ){
        id = vendor;
        match["cpe.vendor"] = new RegExp(vendor, "i");
    }

  const VulnerabilityGraphData = await unifiedCollection
    .aggregate([ 
      { 
        $match: match 
      }, 
      { 
        $group: 
        { 
          _id: 
          { 
            $year: "$published_at" }, Total: 
          { $sum: 1 }, Overflow: 
          { 
            $sum: 
            { 
              $cond: [ 
              { 
                $regexMatch: 
                { 
                  input: "$description", regex: /Overflow/i 
                } }, 1, 0 ] } }, "Memory Corruption": 
          { $sum: 
            { 
              $cond: [ 
              { 
                $regexMatch: 
                { 
                  input: "$description", regex: /Memory Corruption/i } }, 1, 0 ] } }, "SQL Injection": 
          { 
            $sum: 
            { 
              $cond: [ 
              { 
                $regexMatch: 
                { 
                  input: "$description", regex: /SQL Injection/i } }, 1, 0 ] } }, XSS: 
          { 
            $sum: 
            { 
              $cond: [ 
              { 
                $regexMatch: 
                { 
                  input: "$description", regex: /XSS/i } }, 1, 0 ] } }, "Directory Traversal": 
          { 
            $sum: 
            { 
              $cond: [ 
              { 
                $regexMatch: 
                { 
                  input: "$description", regex: /Directory Traversal/i } }, 1, 0 ] } }, "File Inclusion": 
          { 
            $sum: 
            { $cond: [ 
              { 
                $regexMatch: 
                { 
                  input: "$description", regex: /File Inclusion/i } }, 1, 0 ] } }, CSRF: 
          { 
            $sum: 
            { 
              $cond: [ 
              { 
                $regexMatch: 
                { 
                  input: "$description", regex: /CSRF/i } }, 1, 0 ] } }, XXE: 
          { 
            $sum: 
            { 
              $cond: [ 
              { 
                $regexMatch: 
                { 
                  input: "$description", regex: /XXE/i } }, 1, 0 ] } }, SSRF: 
          { 
            $sum: 
            { 
              $cond: [ 
              { 
                $regexMatch: 
                { 
                  input: "$description", regex: /SSRF/i } }, 1, 0 ] } } } }, 
      { 
        $project: 
        { 
          _id: 0, year: "$_id", data: 
          { 
            Total: "$Total", Overflow: "$Overflow", "Memory Corruption": "$Memory Corruption", "SQL Injection": "$SQL Injection", XSS: "$XSS", "Directory Traversal": "$Directory Traversal", "File Inclusion": "$File Inclusion", CSRF: "$CSRF", XXE: "$XXE", SSRF: "$SSRF" } } }, 
      { $sort: { year: 1 } } ]).toArray();

    const result = {
         _id: id,
         data: VulnerabilityGraphData,
    };

    const msg = `Array length of the weakness graph data: ${VulnerabilityGraphData.length}, 
        acknowledgement from insert ${result.acknowledged}`;

    // logger.info(msg);
    // console.log(VulnerabilityGraphData);
    // console.log(result);
      
    return result;

}

const updateCWEHomeStats = async(db) =>{
    const stat = await transformCWEStats(db);
    await db.collection("cwe").updateOne(
        { _id: stat["_id"] },
        { $set: stat },
        { upsert: true }
    );
    logger.info("Updated Home data");
}

const updateCVSSHomeStats = async(db) =>{
    const stat = await transformCVSSStats(db);
    await db.collection("cvss").updateOne(
        { _id: stat["_id"] },
        { $set: stat },
        { upsert: true }
    );
    logger.info("Updated Home data");
}

const updateCWEStats = async(db) =>{
    //get all unqiue vendors
    const vendors = await db.collection("unified_cves").distinct("cpe.vendor");
    const batchSize = 100; 
    let bulk = [];
    //debug
    let count = 0;

    for(const vendor of vendors)
    {
        const vendorName = vendor.replace(/[-\/\\^$.*+?()[\]{}|]/g, '\\$&');
        //get stats
        const stat = await transformCWEStats(db, vendorName);
        bulk.push(stat);
        //debug
        count++;
        if (bulk.length >= batchSize){
            //insert in bulk
            db.collection("testing").insertMany(bulk);
            // reset bulk
            bulk = [];
            logger.info(count);
        }
    }

    // check for any missing stats
    if (bulk.length > 0){
    await db.collection("cwe").insertMany(bulk);
    }
}

const transformCVSSStats = async (db, vendor) => {

    let id = 'home-cvss'
    const match = {
        cvss_score: { $exists: true, $ne: null },
    };

    if (vendor !== undefined && vendor !== null) {
        match["cpe.vendor"] = new RegExp(vendor, "i");
        id = vendor;
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
        _id: id,
        data: {
            scoreRanges,
            totalCount,
            weightedAverage,
        }
    };

}

const updateCVSSStats = async(db) =>{
    //get all unqiue vendors
    const vendors = await db.collection("unified_cves").distinct("cpe.vendor");
    const batchSize = 500; 
    let bulk = [];
    //debug
    let count = 0;

    for( const vendor of vendors)
    {
        const vendorName = vendor.replace(/[-\/\\^$.*+?()[\]{}|]/g, '\\$&');
        // get stats
        const stat = await transformCVSSStats(db, vendorName);
        bulk.push(stat);

        // debug
        count++;
            logger.info(count);
        if (bulk.length >= batchSize) {
            // insert in bulk
            await db.collection("cvss").insertMany(bulk);
            // reset bulk
            bulk = [];
            logger.info(count);
        }
    }

    // check for any missing stats
    if (bulk.length > 0){
    await db.collection("cvss").insertMany(bulk);
    }
}

const updateGraphCollection = async (db) => {
    const unifiedCollection = createUnifiedModel(db);

    // perform all graph related controllers
    await updateCWEStats();
    await updateCVSSStats();

};

module.exports = {
  updateCWEHomeStats,
  updateCVSSHomeStats,
  updateCWEStats,
  updateCVSSStats,
  // updateBoxHomeStats,
  // updateBoxStats,
}
