const fs = require("fs");
const csv = require("csv-parser");
const { ObjectId } = require("mongodb");
const crypto = require("crypto");
const logger = require("../logger");

const activeKeys = new Map();

const generateAuditKey = async (db, userID) => {
  try {
    // Validate input
    if (!userID || typeof userID !== "string") {
      throw new Error("Invalid userID");
    }

    // Generate a 12-character random key
    const key = crypto.randomBytes(8).toString("hex").substring(0, 12);

    // Store key with expiration time (2 minutes from now)
    const expiryTime = Date.now() + 40 * 60 * 1000; // 2 minutes

    activeKeys.set(key, {
      userID,
      expiryTime,
      created: new Date(),
    });

    // Set timeout to remove key after expiration
    setTimeout(() => {
      activeKeys.delete(key);
    }, 40 * 60 * 1000);

    logger.info(`Generated new audit key for user ${userID}`);

    return {
      success: true,
      key,
      expiryTime,
    };
  } catch (error) {
    logger.error(`Error generating audit key: ${error.message}`);
    throw new Error("Failed to generate audit key");
  }
};

/// Helper function to escape regex special characters
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');

function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const getAuditData = async (db, key, page = 1, limit = 10, view = "products") => {
  try {
    if (!key || typeof key !== 'string') throw new Error('Invalid key');

    const keyData = activeKeys.get(key);
    if (!keyData) throw new Error('Invalid or expired audit key');
    if (Date.now() > keyData.expiryTime) {
      activeKeys.delete(key);
      throw new Error('Audit key has expired');
    }

    const totalSteps = 4;
    let currentStep = 0;
    let progressPercent = 0;

    const updateProgress = (step, message, percent) => {
      currentStep = step;
      progressPercent = percent;
      // console.log(`Progress: ${message} - ${percent}%`);
    };

    // Initial progress update
    updateProgress(1, "Scanning installed software", 10);

    const auditCollection = db.collection('audit_cves');
    const auditData = await auditCollection.findOne(
      { key, userID: keyData.userID },
      { sort: { timestamp: -1 } }
    );
    if (!auditData) throw new Error('No audit data found for this key. Please run the script first.');

    updateProgress(2, "Gathering information", 30);

    // Create a cache collection if it doesn't exist
    const cacheCollection = db.collection('cve_match_cache');
    
    // Ensure we have an index on the name field to improve lookup speed
    await cacheCollection.createIndex({ "normalized_name": 1 }, { background: true });
    
    const vulnerabilityCollection = db.collection('unified_cves');
    const matchedVulnerabilities = [];
    const allProducts = new Map();
    const uniqueMatchedEntities = new Set(); // To track unique product names

    const totalSoftware = auditData.software?.length || 0;
    let processedSoftware = 0;

    // Determine the number of workers based on CPU cores (limit to 10 as requested)
    const numCPUs = Math.min(os.cpus().length, 10);
    const batchSize = Math.ceil(totalSoftware / numCPUs);

    // console.log(`Using ${numCPUs} worker threads with batch size of ${batchSize}`);

    // Prepare data batches for workers
    const dataBatches = [];
    for (let i = 0; i < numCPUs; i++) {
      const start = i * batchSize;
      const end = Math.min(start + batchSize, totalSoftware);
      if (start < end) {
        dataBatches.push(auditData.software.slice(start, end));
      }
    }

    // Create worker function as a string (avoiding template literals)
    const workerFunctionStr = [
      'const { parentPort, workerData } = require("worker_threads");',
      'function escapeRegex(string) {',
      '  return string.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");',
      '}',
      '',
      'async function processBatch() {',
      '  const { software, dbConnectionString } = workerData;',
      '  const { MongoClient } = require("mongodb");',
      '  const client = new MongoClient(dbConnectionString);',
      '',
      '  try {',
      '    await client.connect();',
      '    const db = client.db();',
      '    const vulnerabilityCollection = db.collection("unified_cves");',
      '    const cacheCollection = db.collection("cve_match_cache");',
      '    const results = [];',
      '    const batchProducts = new Map();',
      '',
      '    for (const software of workerData.software) {',
      '      if (!software.name) continue;',
      '',
      '      const originalName = software.name.trim();',
      '      const normalizedName = originalName.toLowerCase();',
      '      const normalizedPublisher = software.publisher ? software.publisher.toLowerCase().trim() : "";',
      '',
      '      // First, check the cache for this software name',
      '      const cacheEntry = await cacheCollection.findOne({ normalized_name: normalizedName });',
      '',
      '      if (cacheEntry) {',
      '        console.log(`Cache hit for "${originalName}": Using cached matches`);',
      '        ',
      '        // Store matched data from cache',
      '        results.push({',
      '          software_name: software.name,',
      '          software_version: software.version || "Unknown",',
      '          software_publisher: software.publisher || "Unknown",',
      '          cve_count: cacheEntry.cve_count,',
      '          matched_products: cacheEntry.matched_products',
      '        });',
      '        ',
      '        // Collect products for aggregation',
      '        cacheEntry.matched_products.forEach(p => {',
      '          batchProducts.set(p, (batchProducts.get(p) || 0) + 1);',
      '        });',
      '        ',
      '        continue;',
      '      }',
      '',
      '      // If not in cache, proceed with the intensive matching process',
      '      console.log(`Cache miss for "${originalName}": Performing full matching`);',
      '      ',
      '      const commonWords = ["for", "and", "the", "of", "to", "in", "with", "by", "us", "en", "a", "an"];',
      '      ',
      '      // Get all words without filtering by length',
      '      const allNameParts = normalizedName.split(/\\s+/);',
      '      ',
      '      // Two sets of name parts - one with all words including single letters, one filtered for multi-letter words',
      '      const nameParts = allNameParts.filter(part => ',
      '        part.length >= 3 && !commonWords.includes(part)',
      '      );',
      '      ',
      '      // Special handling for single/double letter words that might be important (like "R")',
      '      const shortNameParts = allNameParts.filter(part => ',
      '        (part.length === 1 || part.length === 2) && !commonWords.includes(part)',
      '      );',
      '',
      '      const matchConditions = [];',
      '',
      '      // Full name matches',
      '      if (normalizedName.length > 0) {',
      '        matchConditions.push({ "cpe.product": { $regex: `\\\\b${escapeRegex(normalizedName)}\\\\b`, $options: "i" } });',
      '      }',
      '',
      '      // Start with first word of product name if no full match - include short names too',
      '      const firstWordParts = [];',
      '      if (nameParts.length > 0) {',
      '        firstWordParts.push(nameParts[0]);',
      '      }',
      '      if (shortNameParts.length > 0) {',
      '        firstWordParts.push(shortNameParts[0]);',
      '      }',
      '      ',
      '      for (const firstPart of firstWordParts) {',
      '        matchConditions.push({ "cpe.product": { $regex: `\\\\b${escapeRegex(firstPart)}\\\\b`, $options: "i" } });',
      '        matchConditions.push({ "vulnerable_cpe": { $regex: `\\\\b${escapeRegex(firstPart)}\\\\b`, $options: "i" } });',
      '      }',
      '',
      '      // Add only for product: middle combinations',
      '      const productCombos = [];',
      '      for (let i = 1; i < nameParts.length - 1; i++) {',
      '        if (nameParts[i] && nameParts[i + 1]) {',
      '          productCombos.push(`${nameParts[i]} ${nameParts[i + 1]}`);',
      '        }',
      '        if (nameParts[i + 2]) {',
      '          productCombos.push(`${nameParts[i]} ${nameParts[i + 1]} ${nameParts[i + 2]}`);',
      '        }',
      '      }',
      '',
      '      const comboParts = [];',
      '      if (nameParts[0] && nameParts[1]) comboParts.push(`${nameParts[0]} ${nameParts[1]}`);',
      '      if (nameParts[1] && nameParts[2]) comboParts.push(`${nameParts[1]} ${nameParts[2]}`);',
      '      if (nameParts[2] && nameParts[3]) comboParts.push(`${nameParts[2]} ${nameParts[3]}`);',
      '      if (nameParts[0] && nameParts[1] && nameParts[2]) comboParts.push(`${nameParts[0]} ${nameParts[1]} ${nameParts[2]}`);',
      '      if (nameParts[1] && nameParts[2] && nameParts[3]) comboParts.push(`${nameParts[1]} ${nameParts[2]} ${nameParts[3]}`);',
      '',
      '      // Add combinations with short names',
      '      for (const shortPart of shortNameParts) {',
      '        if (nameParts[0]) comboParts.push(`${shortPart} ${nameParts[0]}`);',
      '        if (nameParts[1]) comboParts.push(`${shortPart} ${nameParts[1]}`);',
      '        if (nameParts[0] && nameParts[1]) comboParts.push(`${shortPart} ${nameParts[0]} ${nameParts[1]}`);',
      '      }',
      '',
      '      // Add all words and combos to match conditions',
      '      const allParts = [...nameParts, ...shortNameParts, ...productCombos, ...comboParts];',
      '      for (const part of allParts) {',
      '        if (part.length >= 1) { // Changed minimum length to 1 to include single letters',
      '          matchConditions.push({ "cpe.product": { $regex: `\\\\b${escapeRegex(part)}\\\\b`, $options: "i" } });',
      '          matchConditions.push({ "vulnerable_cpe": { $regex: `\\\\b${escapeRegex(part)}\\\\b`, $options: "i" } });',
      '        }',
      '      }',
      '',
      '      if (matchConditions.length === 0) continue;',
      '',
      '      const cveMatches = await vulnerabilityCollection.find({ $or: matchConditions })',
      '        .project({ ',
      '          cve_id: 1, ',
      '          description: 1, ',
      '          cpe: 1, ',
      '          vulnerable_cpe: 1,',
      '          cvss_score: 1,',
      '          cvss_metrics: 1,',
      '          epss: 1,',
      '          published_at: 1,',
      '          is_exploited: 1',
      '        })',
      '        .toArray();',
      '',
      '      if (!cveMatches.length) continue;',
      '',
      '      // Store matches with priority info for sorting later',
      '      const productMatches = new Map(); ',
      '      let hasValidMatch = false;',
      '',
      '      for (const cve of cveMatches) {',
      '        if (Array.isArray(cve.cpe)) {',
      '          for (const cpeItem of cve.cpe) {',
      '            const product = cpeItem.product?.toLowerCase();',
      '            const originalProduct = cpeItem.product;',
      '',
      '            // PRODUCT MATCHING - with combinations',
      '            if (product && product !== "n/a") {',
      '              // Priority 1: Exact full name match',
      '              if (product === normalizedName) {',
      '                productMatches.set(product, { priority: 1, original: originalProduct });',
      '                hasValidMatch = true;',
      '              } ',
      '              // Priority 2: Check for exact match with any of the word combinations',
      '              else {',
      '                // First check 3-word combinations',
      '                let matched = false;',
      '                for (const combo of comboParts.filter(c => c.split(" ").length === 3)) {',
      '                  if (product === combo) {',
      '                    productMatches.set(product, { priority: 2, original: originalProduct });',
      '                    hasValidMatch = true;',
      '                    matched = true;',
      '                    break;',
      '                  }',
      '                }',
      '                ',
      '                // Then check 2-word combinations if not matched yet',
      '                if (!matched) {',
      '                  for (const combo of comboParts.filter(c => c.split(" ").length === 2)) {',
      '                    if (product === combo) {',
      '                      productMatches.set(product, { priority: 3, original: originalProduct });',
      '                      hasValidMatch = true;',
      '                      matched = true;',
      '                      break;',
      '                    }',
      '                  }',
      '                }',
      '                ',
      '                // Then check standard words',
      '                if (!matched) {',
      '                  for (let i = 0; i < nameParts.length; i++) {',
      '                    if (product === nameParts[i]) {',
      '                      productMatches.set(product, { priority: 4 + i, original: originalProduct });',
      '                      hasValidMatch = true;',
      '                      matched = true;',
      '                      break;',
      '                    }',
      '                  }',
      '                }',
      '                ',
      '                // check short words (R, etc)',
      '                if (!matched) {',
      '                  for (let i = 0; i < shortNameParts.length; i++) {',
      '                    if (product === shortNameParts[i]) {',
      '                      productMatches.set(product, { priority: 4 + nameParts.length + i, original: originalProduct });',
      '                      hasValidMatch = true;',
      '                      matched = true;',
      '                      break;',
      '                    }',
      '                  }',
      '                }',
      '              }',
      '            }',
      '          }',
      '        }',
      '',
      '        if (Array.isArray(cve.vulnerable_cpe)) {',
      '          for (const cpeString of cve.vulnerable_cpe) {',
      '            const parts = cpeString.split(":");',
      '            if (parts.length >= 5) {',
      '              const product = parts[4].toLowerCase();',
      '              const originalProduct = parts[4];',
      '',
      '              // PRODUCT MATCHING - with combinations',
      '              if (product && product !== "*" && product !== "-" && product !== "n/a") {',
      '                // Priority 1: Exact full name match',
      '                if (product === normalizedName) {',
      '                  productMatches.set(product, { priority: 1, original: originalProduct });',
      '                  hasValidMatch = true;',
      '                } ',
      '                // Priority 2: Check for exact match with any of the word combinations',
      '                else {',
      '                  // First check 3-word combinations',
      '                  let matched = false;',
      '                  for (const combo of comboParts.filter(c => c.split(" ").length === 3)) {',
      '                    if (product === combo) {',
      '                      productMatches.set(product, { priority: 2, original: originalProduct });',
      '                      hasValidMatch = true;',
      '                      matched = true;',
      '                      break;',
      '                    }',
      '                  }',
      '                  ',
      '                  // Then check 2-word combinations if not matched yet',
      '                  if (!matched) {',
      '                    for (const combo of comboParts.filter(c => c.split(" ").length === 2)) {',
      '                      if (product === combo) {',
      '                        productMatches.set(product, { priority: 3, original: originalProduct });',
      '                        hasValidMatch = true;',
      '                        matched = true;',
      '                        break;',
      '                      }',
      '                    }',
      '                  }',
      '                  ',
      '                  // Then check standard words',
      '                  if (!matched) {',
      '                    for (let i = 0; i < nameParts.length; i++) {',
      '                      if (product === nameParts[i]) {',
      '                        productMatches.set(product, { priority: 4 + i, original: originalProduct });',
      '                        hasValidMatch = true;',
      '                        matched = true;',
      '                        break;',
      '                      }',
      '                    }',
      '                  }',
      '                  ',
      '                  // Finally check short words (R, etc)',
      '                  if (!matched) {',
      '                    for (let i = 0; i < shortNameParts.length; i++) {',
      '                      if (product === shortNameParts[i]) {',
      '                        productMatches.set(product, { priority: 4 + nameParts.length + i, original: originalProduct });',
      '                        hasValidMatch = true;',
      '                        matched = true;',
      '                        break;',
      '                      }',
      '                    }',
      '                  }',
      '                }',
      '              }',
      '            }',
      '          }',
      '        }',
      '      }',
      '',
      '      // Convert from maps and sort by priority',
      '      const sortedProducts = Array.from(productMatches.entries())',
      '        .sort((a, b) => a[1].priority - b[1].priority)',
      '        .map(([_, info]) => info.original)',
      '        .slice(0, 3); // Limit to 3 products',
      '',
      '      console.log(`Matched for "${originalName}": Products → ${JSON.stringify(sortedProducts)}`);',
      '',
      '      if (!hasValidMatch) continue;',
      '',
      '      // Store the match results in the cache collection',
      '      await cacheCollection.updateOne(',
      '        { normalized_name: normalizedName },',
      '        { ',
      '          $set: {',
      '            original_name: originalName,',
      '            normalized_name: normalizedName,',
      '            matched_products: sortedProducts,',
      '            cve_count: cveMatches.length,',
      '            last_updated: new Date()',
      '          }',
      '        },',
      '        { upsert: true }',
      '      );',
      '',
      '      sortedProducts.forEach(p => {',
      '        batchProducts.set(p, (batchProducts.get(p) || 0) + 1);',
      '      });',
      '',
      '      results.push({',
      '        software_name: software.name,',
      '        software_version: software.version || "Unknown",',
      '        software_publisher: software.publisher || "Unknown",',
      '        cve_count: cveMatches.length,',
      '        matched_products: sortedProducts',
      '      });',
      '    }',
      '',
      '    await client.close();',
      '',
      '    // Return the results from this batch',
      '    return {',
      '      matchedVulnerabilities: results,',
      '      batchProducts: Array.from(batchProducts.entries())',
      '    };',
      '  } catch (error) {',
      '    console.error(`Worker error: ${error.message}`);',
      '    await client.close();',
      '    throw error;',
      '  }',
      '}',
      '',
      'processBatch().then(result => {',
      '  parentPort.postMessage({ success: true, data: result });',
      '}).catch(error => {',
      '  parentPort.postMessage({ success: false, error: error.message });',
      '});'
    ].join('\n');

    // Get MongoDB connection string for workers
    const dbConnectionString = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/cve-database';

    // Run workers in parallel
    const workerPromises = dataBatches.map((batch, index) => {
      return new Promise((resolve, reject) => {
        const worker = new Worker(workerFunctionStr, {
          eval: true,
          workerData: {
            software: batch,
            dbConnectionString,
            batchIndex: index
          }
        });

        worker.on('message', (message) => {
          if (message.success) {
            resolve(message.data);
          } else {
            reject(new Error(message.error));
          }
        });

        worker.on('error', reject);
        worker.on('exit', (code) => {
          if (code !== 0) {
            reject(new Error(`Worker stopped with exit code ${code}`));
          }
        });
      });
    });

    updateProgress(3, "Processing matches in parallel", 60);

    const workerResults = await Promise.all(workerPromises);
    
    // Combine results from all workers
    for (const result of workerResults) {
      // Add matched vulnerabilities from each worker
      matchedVulnerabilities.push(...result.matchedVulnerabilities);
      
      // Combine product counts
      for (const [product, count] of result.batchProducts) {
        allProducts.set(product, (allProducts.get(product) || 0) + count);
      }
    }
      
    const processedProducts = Array.from(allProducts.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);

    // Log the unique product names that will be processed
    // console.log(`Unique products to process: ${JSON.stringify(processedProducts.map(p => p.name))}`);

    // Use multi-threading for CVE detail fetching as well
    const uniqueProcessedNames = new Set();
    const cveDetails = [];

    // Create parallel processing for CVE details
    const processEntitiesInParallel = async (entities) => {
      // Create chunks of entities to process
      const chunkSize = Math.ceil(entities.length / numCPUs);
      const chunks = [];
      
      for (let i = 0; i < entities.length; i += chunkSize) {
        chunks.push(entities.slice(i, i + chunkSize));
      }

      // Define worker function for CVE details processing as a string
      const cveWorkerFunctionStr = [
        'const { parentPort, workerData } = require("worker_threads");',
        'const { MongoClient } = require("mongodb");',
        '',
        'async function processCVEDetails() {',
        '  const { entities, dbConnectionString } = workerData;',
        '  const client = new MongoClient(dbConnectionString);',
        '  const results = [];',
        '  const uniqueNames = new Set();',
        '',
        '  try {',
        '    await client.connect();',
        '    const db = client.db();',
        '    const vulnerabilityCollection = db.collection("unified_cves");',
        '',
        '    for (const entity of entities) {',
        '      const name = entity.name;',
        '      ',
        '      // Skip already processed names',
        '      if (uniqueNames.has(name.toLowerCase())) {',
        '        console.log(`Skipping duplicate name: ${name}`);',
        '        continue;',
        '      }',
        '      ',
        '      uniqueNames.add(name.toLowerCase());',
        '      console.log(`Processing product: ${name}`);',
        '',
        '      // Try different capitalizations',
        '      const capitalizations = [',
        '        name,',
        '        name.charAt(0).toUpperCase() + name.slice(1),',
        '        name.toUpperCase()',
        '      ];',
        '      ',
        '      if (name.includes(" ")) {',
        '        const words = name.split(" ");',
        '        const titleCase = words.map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(" ");',
        '        capitalizations.push(titleCase);',
        '      }',
        '',
        '      let foundCVEs = null;',
        '      ',
        '      for (const capitalization of capitalizations) {',
        '        const query = {',
        '          $or: [',
        '            { "cpe.product": capitalization },',
        '            { "vulnerable_cpe": { $regex: capitalization, $options: "i" } }',
        '          ]',
        '        };',
        '',
        '        // Fetch CVEs sorted by published_at date in descending order (newest first)',
        '        // and limit to top 20 most recent CVEs',
        '        const cves = await vulnerabilityCollection.find(query)',
        '          .project({',
        '            cve_id: 1,',
        '            description: 1,',
        '            cvss_score: 1,',
        '            cvss_metrics: 1,',
        '            epss: 1,',
        '            published_at: 1,',
        '            is_exploited: 1',
        '          })',
        '          .sort({ "published_at": -1 })',  // Sort by published date, newest first',
        '          .limit(20)  // Get only top 20 most recent CVEs',
        '          .toArray();',
        '',
        '        if (cves.length > 0) {',
        '          console.log(`Found ${cves.length} recent CVEs for "${capitalization}"`);',
        '          ',
        '          // Format and return CVE data',
        '          foundCVEs = {',
        '            type: "product",',
        '            name: capitalization,',
        '            cves: cves.map(cve => {',
        '              let publishedDate = "Unknown";',
        '              if (cve.published_at) {',
        '                if (cve.published_at.$date) {',
        '                  publishedDate = new Date(cve.published_at.$date).toISOString().split("T")[0];',
        '                } else if (typeof cve.published_at === "string") {',
        '                  publishedDate = new Date(cve.published_at).toISOString().split("T")[0];',
        '                } else if (cve.published_at instanceof Date) {',
        '                  publishedDate = cve.published_at.toISOString().split("T")[0];',
        '                }',
        '              }',
        '',
        '              return {',
        '                cve_id: cve.cve_id,',
        '                description: cve.description,',
        '                cvss_score: cve.cvss_score || ',
        '                           (cve.cvss_metrics?.cvss3?.score || ',
        '                            cve.cvss_metrics?.cvss2?.score || "Unknown"),',
        '                epss_score: cve.epss?.epss_score || "Unknown",',
        '                epss_percentile: cve.epss?.epss_percentile || "Unknown",',
        '                published_date: publishedDate,',
        '                is_exploited: cve.is_exploited === true ? "Yes" : "No"',
        '              };',
        '            })',
        '          };',
        '          ',
        '          break;',
        '        }',
        '      }',
        '',
        '      if (foundCVEs) {',
        '        results.push(foundCVEs);',
        '      }',
        '    }',
        '',
        '    await client.close();',
        '    return results;',
        '  } catch (error) {',
        '    console.error(`CVE worker error: ${error.message}`);',
        '    await client.close();',
        '    throw error;',
        '  }',
        '}',
        '',
        'processCVEDetails().then(result => {',
        '  parentPort.postMessage({ success: true, data: result });',
        '}).catch(error => {',
        '  parentPort.postMessage({ success: false, error: error.message });',
        '});'
      ].join('\n');

      // Run workers for each chunk
      const workerPromises = chunks.map((chunk, index) => {
        return new Promise((resolve, reject) => {
          const worker = new Worker(cveWorkerFunctionStr, {
            eval: true,
            workerData: {
              entities: chunk,
              dbConnectionString,
              chunkIndex: index
            }
          });

          worker.on('message', (message) => {
            if (message.success) {
              resolve(message.data);
            } else {
              reject(new Error(message.error));
            }
          });

          worker.on('error', reject);
          worker.on('exit', (code) => {
            if (code !== 0) {
              reject(new Error(`Worker stopped with exit code ${code}`));
            }
          });
        });
      });

      // Wait for all workers to complete and combine results
      const results = await Promise.all(workerPromises);
      return results.flat();
    };

    // Process products in parallel
    updateProgress(3, "Processing products in parallel", 80);
    const productCVEDetails = await processEntitiesInParallel(processedProducts);
    cveDetails.push(...productCVEDetails);

    updateProgress(4, "Finalizing report", 90);

    // Log summary of CVE details collected
    console.log(`Total unique entities with CVE details: ${cveDetails.length}`);
    console.log(`CVE details summary: ${JSON.stringify(cveDetails.map(item => ({
      type: item.type,
      name: item.name,
      cve_count: item.cves.length
    })))}`);

    const viewData = { products: [], totalPages: 0 };
    // Always use products view now
    const totalItems = processedProducts.length;
    viewData.totalPages = Math.ceil(totalItems / limit);
    viewData.products = processedProducts.slice((page - 1) * limit, page * limit);

    logger.info(`Retrieved optimized audit data for user ${keyData.userID} with key ${key}`);

    return {
      success: true,
      data: {
        _id: auditData._id,
        userID: auditData.userID,
        key: auditData.key,
        timestamp: auditData.timestamp,
        software: auditData.software,
        matchedVulnerabilities,
        viewData,
        cveDetails  // Added the CVE details to the response
      }
    };
  } catch (error) {
    logger.error(`Error retrieving audit data: ${error.message}`);
    throw new Error(error.message || 'Failed to retrieve audit data');
  }
};


const uploadSoftwareAudit = async (db, userID, key, csvFile) => {
  try {
    // Validate inputs
    if (!userID || typeof userID !== "string") {
      throw new Error("Invalid userID");
    }

    if (!key || typeof key !== "string") {
      throw new Error("Invalid authentication key");
    }

    if (!csvFile) {
      throw new Error("No CSV file provided");
    }

    const auditCollection = db.collection("audit_cves");
    const softwareList = [];

    return new Promise((resolve, reject) => {
      fs.createReadStream(csvFile.path)
        .pipe(csv())
        .on("data", (data) => {
          // Normalize keys to lowercase for flexible matching
          const normalizedData = {};
          for (const key in data) {
            normalizedData[key.toLowerCase().trim()] = data[key];
          }

          softwareList.push({
            name:
              normalizedData.name ||
              normalizedData.software ||
              normalizedData.displayname ||
              null,
            version:
              normalizedData.version || normalizedData.displayversion || null,
            installDate:
              normalizedData.installdate ||
              normalizedData.install_date ||
              normalizedData.date ||
              "",
            publisher:
              normalizedData.publisher || normalizedData.vendor || null,
          });
        })
        .on("end", async () => {
          try {
            const auditDocument = {
              userID,
              key,
              timestamp: new Date(),
              software: softwareList,
              processed: false,
            };

            const result = await auditCollection.insertOne(auditDocument);
            fs.unlinkSync(csvFile.path);

            resolve({
              success: true,
              auditId: result.insertedId,
              softwareCount: softwareList.length,
            });
          } catch (error) {
            reject(error);
          }
        })
        .on("error", (error) => {
          fs.unlink(csvFile.path, () => {});
          reject(error);
        });
    });
  } catch (error) {
    logger.error(`Error uploading software audit: ${error.message}`);
    throw new Error("Failed to upload software audit data");
  }
};

const matchAndCacheSoftware = async ({
  software,
  normalizedName,
  normalizedPublisher,
  db,
  cacheCollection,
  vulnerabilityCollection,
}) => {
  const originalName = software.name.trim();

  const commonWords = [
    "for",
    "and",
    "the",
    "of",
    "to",
    "in",
    "with",
    "by",
    "us",
    "en",
    "a",
    "an",
  ];

  const allNameParts = normalizedName.split(/\s+/);
  const nameParts = allNameParts.filter(
    (part) => part.length >= 3 && !commonWords.includes(part)
  );
  const shortNameParts = allNameParts.filter(
    (part) =>
      (part.length === 1 || part.length === 2) && !commonWords.includes(part)
  );

  const matchConditions = [];

  if (normalizedName.length > 0) {
    matchConditions.push({
      "cpe.product": {
        $regex: `\\b${escapeRegex(normalizedName)}\\b`,
        $options: "i",
      },
    });
  }

  if (normalizedPublisher.length > 0) {
    matchConditions.push({
      "cpe.vendor": {
        $regex: `\\b${escapeRegex(normalizedPublisher)}\\b`,
        $options: "i",
      },
    });
  }

  const firstWordParts = [];
  if (nameParts.length > 0) firstWordParts.push(nameParts[0]);
  if (shortNameParts.length > 0) firstWordParts.push(shortNameParts[0]);

  for (const part of firstWordParts) {
    matchConditions.push({
      "cpe.product": { $regex: `\\b${escapeRegex(part)}\\b`, $options: "i" },
    });
    matchConditions.push({
      vulnerable_cpe: { $regex: `\\b${escapeRegex(part)}\\b`, $options: "i" },
    });
  }

  const productCombos = [];
  for (let i = 1; i < nameParts.length - 1; i++) {
    if (nameParts[i] && nameParts[i + 1]) {
      productCombos.push(`${nameParts[i]} ${nameParts[i + 1]}`);
    }
    if (nameParts[i + 2]) {
      productCombos.push(
        `${nameParts[i]} ${nameParts[i + 1]} ${nameParts[i + 2]}`
      );
    }
  }

  const comboParts = [];
  if (nameParts[0] && nameParts[1])
    comboParts.push(`${nameParts[0]} ${nameParts[1]}`);
  if (nameParts[1] && nameParts[2])
    comboParts.push(`${nameParts[1]} ${nameParts[2]}`);
  if (nameParts[2] && nameParts[3])
    comboParts.push(`${nameParts[2]} ${nameParts[3]}`);
  if (nameParts[0] && nameParts[1] && nameParts[2])
    comboParts.push(`${nameParts[0]} ${nameParts[1]} ${nameParts[2]}`);
  if (nameParts[1] && nameParts[2] && nameParts[3])
    comboParts.push(`${nameParts[1]} ${nameParts[2]} ${nameParts[3]}`);

  for (const shortPart of shortNameParts) {
    if (nameParts[0]) comboParts.push(`${shortPart} ${nameParts[0]}`);
    if (nameParts[1]) comboParts.push(`${shortPart} ${nameParts[1]}`);
    if (nameParts[0] && nameParts[1])
      comboParts.push(`${shortPart} ${nameParts[0]} ${nameParts[1]}`);
  }

  const allParts = [
    ...nameParts,
    ...shortNameParts,
    ...productCombos,
    ...comboParts,
  ];
  for (const part of allParts) {
    if (part.length >= 1) {
      matchConditions.push({
        "cpe.product": { $regex: `\\b${escapeRegex(part)}\\b`, $options: "i" },
      });
      matchConditions.push({
        vulnerable_cpe: { $regex: `\\b${escapeRegex(part)}\\b`, $options: "i" },
      });
    }
  }

  if (matchConditions.length === 0) return null;

  const cveMatches = await vulnerabilityCollection
    .find({ $or: matchConditions })
    .project({
      cpe: 1,
      vulnerable_cpe: 1,
    })
    .toArray();

  if (!cveMatches.length) return null;

  const vendorMatches = new Map();
  const productMatches = new Map();
  let hasValidMatch = false;

  for (const cve of cveMatches) {
    const allCPEs = [];

    if (Array.isArray(cve.cpe)) {
      allCPEs.push(
        ...cve.cpe.map((c) => ({ vendor: c.vendor, product: c.product }))
      );
    }
    if (Array.isArray(cve.vulnerable_cpe)) {
      for (const cpeString of cve.vulnerable_cpe) {
        const parts = cpeString.split(":");
        if (parts.length >= 5) {
          allCPEs.push({ vendor: parts[3], product: parts[4] });
        }
      }
    }

    for (const { vendor, product } of allCPEs) {
      const v = vendor?.toLowerCase();
      const p = product?.toLowerCase();
      const originalVendor = vendor;
      const originalProduct = product;

      // Vendor Matching
      if (v && v !== "n/a") {
        if (v === normalizedName) {
          vendorMatches.set(v, { priority: 1, original: originalVendor });
          hasValidMatch = true;
        } else if (
          v === normalizedPublisher ||
          normalizedPublisher.includes(v) ||
          v.includes(normalizedPublisher)
        ) {
          vendorMatches.set(v, { priority: 2, original: originalVendor });
          hasValidMatch = true;
        } else if (nameParts.length > 0 && v === nameParts[0]) {
          vendorMatches.set(v, { priority: 3, original: originalVendor });
          hasValidMatch = true;
        }
      }

      // Product Matching
      if (p && p !== "n/a") {
        if (p === normalizedName) {
          productMatches.set(p, { priority: 1, original: originalProduct });
          hasValidMatch = true;
        } else if (comboParts.includes(p)) {
          productMatches.set(p, { priority: 2, original: originalProduct });
          hasValidMatch = true;
        } else if (nameParts.includes(p)) {
          productMatches.set(p, { priority: 4, original: originalProduct });
          hasValidMatch = true;
        }
      }
    }
  }

  if (!hasValidMatch) return null;

  const sortedVendors = Array.from(vendorMatches.entries())
    .sort((a, b) => a[1].priority - b[1].priority)
    .map(([_, info]) => info.original)
    .slice(0, 3);

  const sortedProducts = Array.from(productMatches.entries())
    .sort((a, b) => a[1].priority - b[1].priority)
    .map(([_, info]) => info.original)
    .slice(0, 3);

  await cacheCollection.updateOne(
    { normalized_name: normalizedName },
    {
      $set: {
        original_name: originalName,
        normalized_name: normalizedName,
        matched_vendors: sortedVendors,
        matched_products: sortedProducts,
        cve_count: cveMatches.length,
        last_updated: new Date(),
      },
    },
    { upsert: true }
  );

  return {
    matched_vendors: sortedVendors,
    matched_products: sortedProducts,
    cve_count: cveMatches.length,
  };
};

module.exports = {
  generateAuditKey,
  getAuditData,
  uploadSoftwareAudit,
};
