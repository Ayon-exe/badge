const { ObjectId } = require('mongodb');
const logger = require('../logger');

// Models for the three sources and unified collection
const createCVEModel = (db) => db.collection('cves');
const createCVEMapModel = (db) => db.collection('cvemap');
const createnvdModel = (db) => db.collection('nvd');
const createUnifiedModel = (db) => db.collection('unified_cves');

// Unified Merge Function
async function parseUnifiedData(db) {
    const cveCollection = createCVEModel(db);
    const cvemapCollection = createCVEMapModel(db);
    const nvdCollection = createnvdModel(db);
    const unifiedCollection = createUnifiedModel(db);
    const batchSize = 1000;
    let allCVEIds = [];

    // Fetch only CVE IDs with the tag 'R'
    const mitreIds = await cveCollection.distinct('cve_id', { tag: 'R' });
    logger.info(`Found ${mitreIds.length} CVE IDs with tag 'R' in cves[collection]`); // Log the number of CVE IDs found

    const nvdIds = await nvdCollection.distinct('cve_id', { tag: 'R' });
    logger.info(`Found ${nvdIds.length} CVE IDs with tag 'R' in nvd[collection]`); // Log the number of CVE IDs found

    if (nvdIds.length === 0 && mitreIds.length === 0) {
      logger.info('No CVE IDs found with tag "R".');
      return;
    }

    mitreIds.length ?  allCVEIds = mitreIds : allCVEIds = nvdIds ;

    // Prepare bulk operations
    let unifiedBulkOps = [];
    let mitreBulkOps = [];
    let nvdBulkOps = [];
    let cvemapBulkOps = [];

// Fetch data for all CVE IDs in a single query
    const [mitreDataList, nvdDataList, cvemapDataList] = await Promise.all([
        cveCollection.find({ cve_id: { $in: allCVEIds }, tag: 'R' }).toArray(),
        nvdCollection.find({ cve_id: { $in: allCVEIds }, tag: 'R' }).toArray(),
        cvemapCollection.find({ cve_id: { $in: allCVEIds }, tag: 'R' }).toArray()
    ]);

  //function to perform Bulk
    async function performBulkWrite() {
         if (unifiedBulkOps.length > 0) {
            await unifiedCollection.bulkWrite(unifiedBulkOps);
        }
        if (mitreBulkOps.length > 0) {
            await cveCollection.updateMany(
                { cve_id: { $in : mitreBulkOps } },
                { $set : { tag: 'N' } }
                    // update: { $set: { tag: 'N' } }
            );
        }
        if (nvdBulkOps.length > 0) {
            await nvdCollection.updateMany(
                { cve_id: { $in : nvdBulkOps } },
                { $set : { tag: 'N' } }
            );
        }
        if (cvemapBulkOps.length > 0) {
            await cvemapCollection.updateMany(
                { cve_id: { $in : cvemapBulkOps } },
                { $set : { tag: 'N' } }
            );
        }
    }

 // Create a map for quick access
    const mitreDataMap = new Map(mitreDataList.map(data => [data.cve_id, data]));
    const nvdDataMap = new Map(nvdDataList.map(data => [data.cve_id, data]));
    const cvemapDataMap = new Map(cvemapDataList.map(data => [data.cve_id, data]));

  function formatName(str) {
    str = str.replace(/_/g, ' ');
    if ( str.length > 3) {
      return str
        .split(' ') // Split the string into an array of words
        .map(word => word.charAt(0).toUpperCase() + word.slice(1)) // Capitalize the first letter of each word
        .join(' '); // Join the array back into a string
    } else {
      return str.toUpperCase();
    }
  }

  function parseVulnerableCpe(vulnerableCpe) {

    if (!Array.isArray(vulnerableCpe)) { // Check if it's not an array
      return null; // Return null if it's not an array or is null/undefined
    }

    return vulnerableCpe.map(cpe => {
      const parts = cpe.split(':');
      return {
        version: formatName(parts[1]),
        product_code: formatName(parts[2]),
        vendor: formatName(parts[3]),
        product: formatName(parts[4]),
        version: formatName(parts[5]),
        update: formatName(parts[6]),
        edition: formatName(parts[7]),
        lang: formatName(parts[8]),
        sw_edition: formatName(parts[9]),
        target_sw: formatName(parts[10]),
        target_hw: formatName(parts[11]),
        other: formatName(parts[12])
      };
    });
  }

  
 // Iterate through all CVE IDs with tag 'R'
    for (const cveId of allCVEIds) {
        const mitreData = mitreDataMap.get(cveId);
        const nvdData = nvdDataMap.get(cveId);
        const cvemapData = cvemapDataMap.get(cveId);
        
      // Merging logic with preference: MITRE > NVD > CVEMap
        const unifiedData = {
            _id: cveId,
            cve_id: cveId,
            description: mitreData?.description || nvdData?.description || cvemapData?.description || 'No description available',
            severity: mitreData?.cvss_data?.baseSeverity || nvdData?.severity || cvemapData?.severity || null,
            cvss_score: mitreData?.cvss_data?.baseScore || nvdData?.cvss_score || cvemapData?.cvss_score || null,
            cvss_metrics: mitreData?.cvss_data || nvdData?.cvss_metrics || cvemapData?.cvss_metrics || null,
            weaknesses: mitreData?.cwe_data || nvdData?.weaknesses || cvemapData?.weaknesses || [],
            epss: cvemapData?.epss || null,
            cpe: mitreData?.cpe_data || nvdData?.cpe_data || null, // || mitreData?.cpe_data 
            references: mitreData?.references 
              || (nvdData?.references ? nvdData.references.map(reference => reference.url) : null )
              || cvemapData?.references 
              || [],
            vendor_advisory: nvdData?.vendor_advisory  || (cvemapData?.vendor_advisory ? [cvemapData?.vendor_advisory] : null) || [],
            is_template: mitreData?.is_template || nvdData?.is_template || cvemapData?.is_template || false,
            is_exploited: mitreData?.is_exploited || nvdData?.is_exploited || cvemapData?.is_exploited || false,
            assignee: cvemapData?.assignee || null,
            published_at: mitreData?.published_date || nvdData?.published_at || cvemapData?.published_at || null,
            updated_at: mitreData?.last_modified || nvdData?.updated_at || cvemapData?.updated_at || null,
            hackerone: null,
            age_in_days: cvemapData?.age_in_days || null,
            vuln_status: cvemapData?.vuln_status || null,
            is_poc: cvemapData?.is_poc || false,
            is_remote: cvemapData?.is_remote || false,
            is_oss: cvemapData?.is_oss || false,
            vulnerable_cpe: nvdData?.vulnerable_cpe || cvemapData?.vulnerable_cpe || [],
            patch_url: cvemapData?.patch_url || nvdData?.patch_url || [],
            kev: cvemapData?.kev || null,
            nuclei_templates: cvemapData?.nuclei_templates || null,
            oss: cvemapData?.oss || null,
            poc: cvemapData?.poc || null,
            shodan: cvemapData?.shodan || null,
            source: 'Unified',  // Merged data comes from multiple sources
            tag: 'R'  // Mark as 'R' in the unified collection after merging (R: required for futher processing)
        };


        // Assuming patch_url is an array and references is also an array
        const patchUrls = unifiedData.patch_url || [];
        const references = unifiedData.references || [];

        // Create a Set for faster lookup of patch URLs
        const patchUrlSet = new Set(patchUrls);

        // Filter out references that are present in the patch_url array
        unifiedData.references = references.filter(reference => !patchUrlSet.has(reference));

        // Assuming vendor_advisory is an array 
        const vendorAdvisory = unifiedData.vendor_advisory || [];

        // Create a Set for faster lookup of patch URLs
        const vendorAdvisorySet = new Set(vendorAdvisory);

        unifiedData.references = references.filter(reference => !vendorAdvisorySet.has(reference));

        // Add to unified bulk operations
        unifiedBulkOps.push({
            updateOne: {
                filter: { _id: cveId },
                update: { $set: unifiedData },
                upsert: true
            }
        });

        // Update original collections with 'N' after processing
        if (mitreData) {
            mitreBulkOps.push(cveId);
        }

        if (nvdData) {
            nvdBulkOps.push(cveId);
                    // update: { $set: { tag: 'N' } }
        }

        if (cvemapData) {
            cvemapBulkOps.push(cveId);
        }


        // Execute bulk write operations if the batch size is reached
        if (unifiedBulkOps.length >= batchSize) {
            await performBulkWrite();

            // Reset bulk operations
            unifiedBulkOps = [];
            mitreBulkOps = [];
            nvdBulkOps = [];
            cvemapBulkOps = [];
            // count += batchSize;
        }
    }

    // Perform any remaining bulk write operations
    if (unifiedBulkOps.length > 0) {
        await performBulkWrite();
    }
    // console.log(count + " batch completed");
}

module.exports = { parseUnifiedData };

// const { ObjectId } = require('mongodb');

// // Models for the three sources and unified collection
// const createCVEModel = (db) => db.collection('cves');
// const createCVEMapModel = (db) => db.collection('cvemap');
// const createnvdModel = (db) => db.collection('nvd');
// const createUnifiedModel = (db) => db.collection('unified_cves');

// // Unified Merge Function
// async function parseUnifiedData(db) {
//     const cveCollection = createCVEModel(db);
//     const cveMapCollection = createCVEMapModel(db);
//     const nvdCollection = createnvdModel(db);
//     const unifiedCollection = createUnifiedModel(db);

//     const allCVEIds = await cveCollection.distinct('cve_id');
//     logger.info(`Found ${allCVEIds.length} CVE IDs`); // Log the number of CVE IDs found

//     if (allCVEIds.length === 0) {
//         logger.info('No CVE IDs found in MITRE data.');
//         return;
//     }

//     // Prepare bulk operations
//     const unifiedBulkOps = [];
//     const mitreBulkOps = [];
//     const nvdBulkOps = [];
//     const cvemapBulkOps = [];

//     // Remove the slicing to process all CVE IDs
//     for (const cveId of allCVEIds) {
//         // Fetch data from each source (MITRE, NVD, CVEMap)
//         const mitreData = await cveCollection.findOne({ cve_id: cveId });
//         const nvdData = await nvdCollection.findOne({ cve_id: cveId });
//         const cvemapData = await cveMapCollection.findOne({ cve_id: cveId });

//         // Merging logic with preference: MITRE > NVD > CVEMap
//         const unifiedData = {
//             cve_id: cveId,
//             description: mitreData?.description || nvdData?.description || cvemapData?.description || 'No description available',
//             severity: mitreData?.cvss_data?.baseSeverity || nvdData?.severity || cvemapData?.severity || null,
//             cvss_score: mitreData?.cvss_data?.baseScore || nvdData?.cvss_score || cvemapData?.cvss_score || null,
//             cvss_metrics: mitreData?.cvss_data || nvdData?.cvss_metrics || cvemapData?.cvss_metrics || null,
//             weaknesses: mitreData?.cwe_data || nvdData?.weaknesses || cvemapData?.weaknesses || [],
//             epss: cvemapData?.epss || null,  // Assuming CVEMap has this data
//             cpe: mitreData?.cpe_data || null, // Adjusted for CPE data source
//             references: mitreData?.references || nvdData?.references || cvemapData?.vendor_advisory || [],
//             vendor_advisory: cvemapData?.vendor_advisory || nvdData?.references || null,
//             is_template: mitreData?.is_template || nvdData?.is_template || cvemapData?.is_template || false,
//             is_exploited: mitreData?.is_exploited || nvdData?.is_exploited || cvemapData?.is_exploited || false,
//             assignee: cvemapData?.assignee || null,
//             published_at: mitreData?.published_date || nvdData?.published_at || cvemapData?.published_at || null,
//             updated_at: mitreData?.last_modified || nvdData?.updated_at || cvemapData?.updated_at || null,
//             hackerone: null,  // If applicable
//             age_in_days: cvemapData?.age_in_days || null,
//             vuln_status: cvemapData?.vuln_status || null,
//             is_poc: cvemapData?.is_poc || false,
//             is_remote: cvemapData?.is_remote || false,
//             is_oss: cvemapData?.is_oss || false,
//             vulnerable_cpe: mitreData?.cpe_data || nvdData?.vulnerable_cpe || cvemapData?.vulnerable_cpe || [],
//             source: 'Unified',  // Merged data comes from multiple sources
//             tag: 'N'  // Mark as 'N' in the unified collection after merging
//         };

//         // Add to unified bulk operations
//         unifiedBulkOps.push({
//             updateOne: {
//                 filter: { cve_id: cveId },
//                 update: { $set: unifiedData },
//                 upsert: true
//             }
//         });

//         // Update original collections with 'N' after processing
//         if (mitreData) {
//             mitreBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }

//         if (nvdData) {
//             nvdBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }

//         if (cvemapData) {
//             cvemapBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }
//     }

//     // Execute bulk write operations
//     if (unifiedBulkOps.length > 0) {
//         await unifiedCollection.bulkWrite(unifiedBulkOps);
//     }

//     if (mitreBulkOps.length > 0) {
//         await cveCollection.bulkWrite(mitreBulkOps);
//     }

//     if (nvdBulkOps.length > 0) {
//         await nvdCollection.bulkWrite(nvdBulkOps);
//     }

//     if (cvemapBulkOps.length > 0) {
//         await cveMapCollection.bulkWrite(cvemapBulkOps);
//     }

//     logger.info('Unified data processing completed.');
// }

// module.exports = { parseUnifiedData };




// const { ObjectId } = require('mongodb');

// // Models for the three sources and unified collection
// const createCVEModel = (db) => db.collection('cves');
// const createCVEMapModel = (db) => db.collection('cvemap');
// const createnvdModel = (db) => db.collection('nvd');
// const createUnifiedModel = (db) => db.collection('unified_cves');

// // Unified Merge Function
// async function parseUnifiedData(db) {
//     const cveCollection = createCVEModel(db);
//     const cveMapCollection = createCVEMapModel(db);
//     const nvdCollection = createnvdModel(db);
//     const unifiedCollection = createUnifiedModel(db);

//     const allCVEIds = await cveCollection.distinct('cve_id');
//     // logger.info(`Found ${allCVEIds.length} CVE IDs`);

//     if (allCVEIds.length === 0) {
//         logger.info('No CVE IDs found in MITRE data.');
//         return;
//     }

//     // Prepare bulk operations
//     const unifiedBulkOps = [];
//     const mitreBulkOps = [];
//     const nvdBulkOps = [];
//     const cvemapBulkOps = [];
//     const sampleCVEIds = allCVEIds.slice(0, 10);
//     for (const cveId of sampleCVEIds) {
//         // Fetch data from each source (MITRE, NVD, CVEMap)
//         const mitreData = await cveCollection.findOne({ cve_id: cveId });
//         const nvdData = await nvdCollection.findOne({ cve_id: cveId });
//         const cvemapData = await cveMapCollection.findOne({ cve_id: cveId });
//         // logger.info(`MITRE Data for ${cveId}: ${!!mitreData}`);
//         // logger.info(`NVD Data for ${cveId}: ${!!nvdData}`);
//         // logger.info(`CVEMap Data for ${cveId}: ${!!cvemapData}`);

//         // Merging logic with preference: MITRE > NVD > CVEMap
//         const unifiedData = {
//             cve_id: cveId,
//             description: mitreData?.description || nvdData?.description || cvemapData?.description || 'No description available',
//             severity: mitreData?.severity || nvdData?.severity || cvemapData?.severity || null,
//             cvss_score: mitreData?.cvss_score || nvdData?.cvss_score || cvemapData?.cvss_score || null,
//             cvss_metrics: mitreData?.cvss_metrics || nvdData?.cvss_metrics || cvemapData?.cvss_metrics || null,
//             weaknesses: mitreData?.weaknesses || nvdData?.weaknesses || cvemapData?.weaknesses || [],
//             epss: mitreData?.epss || nvdData?.epss || cvemapData?.epss || null,
//             cpe: mitreData?.cpe || nvdData?.cpe || cvemapData?.cpe || null,
//             references: mitreData?.references || nvdData?.references || cvemapData?.references || [],
//             vendor_advisory: mitreData?.vendor_advisory || nvdData?.vendor_advisory || cvemapData?.vendor_advisory || null,
//             is_template: mitreData?.is_template || nvdData?.is_template || cvemapData?.is_template || false,
//             is_exploited: mitreData?.is_exploited || nvdData?.is_exploited || cvemapData?.is_exploited || false,
//             assignee: mitreData?.assignee || nvdData?.assignee || cvemapData?.assignee || null,
//             published_at: mitreData?.published_at || nvdData?.published_at || cvemapData?.published_at || null,
//             updated_at: mitreData?.updated_at || nvdData?.updated_at || cvemapData?.updated_at || null,
//             hackerone: mitreData?.hackerone || nvdData?.hackerone || cvemapData?.hackerone || null,
//             age_in_days: mitreData?.age_in_days || nvdData?.age_in_days || cvemapData?.age_in_days || null,
//             vuln_status: mitreData?.vuln_status || nvdData?.vuln_status || cvemapData?.vuln_status || null,
//             is_poc: mitreData?.is_poc || nvdData?.is_poc || cvemapData?.is_poc || false,
//             is_remote: mitreData?.is_remote || nvdData?.is_remote || cvemapData?.is_remote || false,
//             is_oss: mitreData?.is_oss || nvdData?.is_oss || cvemapData?.is_oss || false,
//             vulnerable_cpe: mitreData?.vulnerable_cpe || nvdData?.vulnerable_cpe || cvemapData?.vulnerable_cpe || [],
//             source: 'Unified',  // Merged data comes from multiple sources
//             tag: 'N'  // Mark as 'N' in the unified collection after merging
//         };

//         // Add to unified bulk operations
//         unifiedBulkOps.push({
//             updateOne: {
//                 filter: { cve_id: cveId },
//                 update: { $set: unifiedData },
//                 upsert: true
//             }
//         });

//         // Update original collections with 'N' after processing
//         if (mitreData) {
//             mitreBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }

//         if (nvdData) {
//             nvdBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }

//         if (cvemapData) {
//             cvemapBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: { tag: 'N' } }
//                 }
//             });
//         }
//     }

//     // Execute bulk write operations
//     if (unifiedBulkOps.length > 0) {
//         await unifiedCollection.bulkWrite(unifiedBulkOps);
//     }

//     if (mitreBulkOps.length > 0) {
//         await cveCollection.bulkWrite(mitreBulkOps);
//     }

//     if (nvdBulkOps.length > 0) {
//         await nvdCollection.bulkWrite(nvdBulkOps);
//     }

//     if (cvemapBulkOps.length > 0) {
//         await cveMapCollection.bulkWrite(cvemapBulkOps);
//     }

//     logger.info('Unified CVE data merged successfully.');
// }

// module.exports = {
//     parseUnifiedData
// };


// const { ObjectId } = require('mongodb');

// // Models for the three sources and unified collection
// const createCVEModel = (db) => db.collection('cves');
// const createCVEMapModel = (db) => db.collection('cvemap');
// const createnvdModel = (db) => db.collection('nvd');
// const createUnifiedModel = (db) => db.collection('unified_cves');

// // Unified Merge Function with Batch Processing
// async function parseUnifiedData(db) {
//     const cveCollection = createCVEModel(db);
//     const cveMapCollection = createCVEMapModel(db);
//     const nvdCollection = createnvdModel(db);
//     const unifiedCollection = createUnifiedModel(db);

//     // Fetch CVE data from MITRE, sorting by published_at descending
//     const mitreData = await cveCollection.find({ tag: 'R' }).sort({ published_at: -1 }).toArray();
//     logger.info(`Found ${mitreData.length} CVE entries from MITRE with tag 'R'`);

//     if (mitreData.length === 0) {
//         logger.info('No CVE entries found in MITRE with tag "R".');
//         return;
//     }

//     // Define batch size
//     const batchSize = 1000;

//     for (let i = 0; i < mitreData.length; i += batchSize) {
//         const batchMitreData = mitreData.slice(i, i + batchSize);
//         logger.info(`Processing batch from ${i + 1} to ${i + batchSize}`);

//         // Prepare bulk operations
//         const unifiedBulkOps = [];
//         const nvdBulkOps = [];
//         const cvemapBulkOps = [];

//         for (const mitreEntry of batchMitreData) {
//             const cveId = mitreEntry.cve_id;

//             // Fetch data from NVD and CVEMap
//             const nvdData = await nvdCollection.findOne({ cve_id: cveId, tag: 'R' });
//             const cvemapData = await cveMapCollection.findOne({ cve_id: cveId, tag: 'R' });

//             // Merging logic: prefer MITRE, then NVD, then CVEMap
//             const unifiedData = {
//                 cve_id: cveId,
//                 description: mitreEntry.description || nvdData?.description || cvemapData?.description || 'No description available',
//                 severity: mitreEntry.severity || nvdData?.severity || cvemapData?.severity || null,
//                 cvss_score: mitreEntry.cvss_score || nvdData?.cvss_score || cvemapData?.cvss_score || null,
//                 cvss_metrics: mitreEntry.cvss_metrics || nvdData?.cvss_metrics || cvemapData?.cvss_metrics || null,
//                 weaknesses: mitreEntry.weaknesses || nvdData?.weaknesses || cvemapData?.weaknesses || [],
//                 epss: mitreEntry.epss || nvdData?.epss || cvemapData?.epss || null,
//                 cpe: mitreEntry.cpe || nvdData?.cpe || cvemapData?.cpe || null,
//                 references: mitreEntry.references || nvdData?.references || cvemapData?.references || [],
//                 vendor_advisory: mitreEntry.vendor_advisory || nvdData?.vendor_advisory || cvemapData?.vendor_advisory || null,
//                 is_template: mitreEntry.is_template || nvdData?.is_template || cvemapData?.is_template || false,
//                 is_exploited: mitreEntry.is_exploited || nvdData?.is_exploited || cvemapData?.is_exploited || false,
//                 assignee: mitreEntry.assignee || nvdData?.assignee || cvemapData?.assignee || null,
//                 published_at: mitreEntry.published_at || nvdData?.published_at || cvemapData?.published_at || null,
//                 updated_at: mitreEntry.updated_at || nvdData?.updated_at || cvemapData?.updated_at || null,
//                 hackerone: mitreEntry.hackerone || nvdData?.hackerone || cvemapData?.hackerone || null,
//                 age_in_days: mitreEntry.age_in_days || nvdData?.age_in_days || cvemapData?.age_in_days || null,
//                 vuln_status: mitreEntry.vuln_status || nvdData?.vuln_status || cvemapData?.vuln_status || null,
//                 is_poc: mitreEntry.is_poc || nvdData?.is_poc || cvemapData?.is_poc || false,
//                 is_remote: mitreEntry.is_remote || nvdData?.is_remote || cvemapData?.is_remote || false,
//                 is_oss: mitreEntry.is_oss || nvdData?.is_oss || cvemapData?.is_oss || false,
//                 vulnerable_cpe: mitreEntry.vulnerable_cpe || nvdData?.vulnerable_cpe || cvemapData?.vulnerable_cpe || [],
//                 source: 'Unified',  // Merged data comes from multiple sources
//                 tag: 'N'  // Mark as 'N' in the unified collection after merging
//             };

//             // Add to unified bulk operations
//             unifiedBulkOps.push({
//                 updateOne: {
//                     filter: { cve_id: cveId },
//                     update: { $set: unifiedData },
//                     upsert: true
//                 }
//             });

//             // Update original collections with 'N' after processing
//             if (nvdData) {
//                 nvdBulkOps.push({
//                     updateOne: {
//                         filter: { cve_id: cveId },
//                         update: { $set: { tag: 'N' } }
//                     }
//                 });
//             }

//             if (cvemapData) {
//                 cvemapBulkOps.push({
//                     updateOne: {
//                         filter: { cve_id: cveId },
//                         update: { $set: { tag: 'N' } }
//                     }
//                 });
//             }
//         }

//         // Execute bulk write operations for this batch
//         if (unifiedBulkOps.length > 0) {
//             await unifiedCollection.bulkWrite(unifiedBulkOps);
//             unifiedBulkOps.length = 0; // Clear the bulk operations
//         }

//         if (nvdBulkOps.length > 0) {
//             await nvdCollection.bulkWrite(nvdBulkOps);
//             nvdBulkOps.length = 0;
//         }

//         if (cvemapBulkOps.length > 0) {
//             await cveMapCollection.bulkWrite(cvemapBulkOps);
//             cvemapBulkOps.length = 0;
//         }

//         logger.info(`Batch from ${i + 1} to ${i + batchSize} processed successfully.`);
//     }

//     logger.info('All CVE data processed and merged.');
// }

// module.exports = {
//     parseUnifiedData
// };




            
