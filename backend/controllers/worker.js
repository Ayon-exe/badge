// audit-worker.js
const { parentPort, workerData } = require('worker_threads');
const { MongoClient } = require('mongodb');

// Function to escape regex special chars (copied from main file)
// Function to escape regex special chars
function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  
  // Process a single software item
  async function processSoftware(db, software, vulnerabilityCollection, cacheCollection) {
    try {
      if (!software.name) return null;
  
      const originalName = software.name.trim();
      const normalizedName = originalName.toLowerCase();
      const normalizedPublisher = software.publisher ? software.publisher.toLowerCase().trim() : '';
  
      // First, check the cache for this software name
      const cacheEntry = await cacheCollection.findOne({ 
        normalized_name: normalizedName 
      });
  
      if (cacheEntry) {
        console.log(`Cache hit for "${originalName}": Using cached matches`);
        
        return {
          software_name: software.name,
          software_version: software.version || "Unknown",
          software_publisher: software.publisher || "Unknown",
          cve_count: cacheEntry.cve_count,
          matched_vendors: cacheEntry.matched_vendors,
          matched_products: cacheEntry.matched_products,
          cached: true
        };
      }
  
      // If not in cache, proceed with the intensive matching process
      console.log(`Cache miss for "${originalName}": Performing full matching`);
      
      const commonWords = ['for', 'and', 'the', 'of', 'to', 'in', 'with', 'by', 'us', 'en', 'a', 'an'];
      
      // Get all words without filtering by length
      const allNameParts = normalizedName.split(/\s+/);
      
      // Two sets of name parts - one with all words including single letters, one filtered for multi-letter words
      const nameParts = allNameParts.filter(part => 
        part.length >= 3 && !commonWords.includes(part)
      );
      
      // Special handling for single/double letter words that might be important (like "R")
      const shortNameParts = allNameParts.filter(part => 
        (part.length === 1 || part.length === 2) && !commonWords.includes(part)
      );
  
      const matchConditions = [];
  
      // Full name matches
      if (normalizedName.length > 0) {
        matchConditions.push({ "cpe.product": { $regex: `\\b${escapeRegex(normalizedName)}\\b`, $options: "i" } });
      }
      if (normalizedPublisher.length > 0) {
        matchConditions.push({ "cpe.vendor": { $regex: `\\b${escapeRegex(normalizedPublisher)}\\b`, $options: "i" } });
      }
  
      // Start with first word of product name if no full match - include short names too
      const firstWordParts = [];
      if (nameParts.length > 0) {
        firstWordParts.push(nameParts[0]);
      }
      if (shortNameParts.length > 0) {
        firstWordParts.push(shortNameParts[0]);
      }
      
      for (const firstPart of firstWordParts) {
        matchConditions.push({ "cpe.product": { $regex: `\\b${escapeRegex(firstPart)}\\b`, $options: "i" } });
        matchConditions.push({ "vulnerable_cpe": { $regex: `\\b${escapeRegex(firstPart)}\\b`, $options: "i" } });
      }
  
      // Add only for product (not vendors): middle combinations
      const productCombos = [];
      for (let i = 1; i < nameParts.length - 1; i++) {
        if (nameParts[i] && nameParts[i + 1]) {
          productCombos.push(`${nameParts[i]} ${nameParts[i + 1]}`);
        }
        if (nameParts[i + 2]) {
          productCombos.push(`${nameParts[i]} ${nameParts[i + 1]} ${nameParts[i + 2]}`);
        }
      }
  
      const comboParts = [];
      if (nameParts[0] && nameParts[1]) comboParts.push(`${nameParts[0]} ${nameParts[1]}`);
      if (nameParts[1] && nameParts[2]) comboParts.push(`${nameParts[1]} ${nameParts[2]}`);
      if (nameParts[2] && nameParts[3]) comboParts.push(`${nameParts[2]} ${nameParts[3]}`);
      if (nameParts[0] && nameParts[1] && nameParts[2]) comboParts.push(`${nameParts[0]} ${nameParts[1]} ${nameParts[2]}`);
      if (nameParts[1] && nameParts[2] && nameParts[3]) comboParts.push(`${nameParts[1]} ${nameParts[2]} ${nameParts[3]}`);
  
      // Add combinations with short names
      for (const shortPart of shortNameParts) {
        if (nameParts[0]) comboParts.push(`${shortPart} ${nameParts[0]}`);
        if (nameParts[1]) comboParts.push(`${shortPart} ${nameParts[1]}`);
        if (nameParts[0] && nameParts[1]) comboParts.push(`${shortPart} ${nameParts[0]} ${nameParts[1]}`);
      }
  
      // Add all words and combos to match conditions
      const allParts = [...nameParts, ...shortNameParts, ...productCombos, ...comboParts];
      for (const part of allParts) {
        if (part.length >= 1) { // Changed minimum length to 1 to include single letters
          matchConditions.push({ "cpe.product": { $regex: `\\b${escapeRegex(part)}\\b`, $options: "i" } });
          matchConditions.push({ "vulnerable_cpe": { $regex: `\\b${escapeRegex(part)}\\b`, $options: "i" } });
        }
      }
  
      if (matchConditions.length === 0) return null;
  
      const cveMatches = await vulnerabilityCollection.find({ $or: matchConditions })
        .project({ 
          cve_id: 1, 
          description: 1, 
          cpe: 1, 
          vulnerable_cpe: 1,
          cvss_score: 1,
          cvss_metrics: 1,
          epss: 1,
          published_at: 1,
          is_exploited: 1
        })
        .toArray();
  
      if (!cveMatches.length) return null;
  
      // Store matches with priority info for sorting later
      const vendorMatches = new Map(); 
      const productMatches = new Map(); 
      let hasValidMatch = false;
  
      for (const cve of cveMatches) {
        if (Array.isArray(cve.cpe)) {
          for (const cpeItem of cve.cpe) {
            const vendor = cpeItem.vendor?.toLowerCase();
            const product = cpeItem.product?.toLowerCase();
            const originalVendor = cpeItem.vendor;
            const originalProduct = cpeItem.product;
  
            // VENDOR MATCHING
            if (vendor && vendor !== 'n/a') {
              // Priority 1: Exact full name match
              if (vendor === normalizedName) {
                vendorMatches.set(vendor, { priority: 1, original: originalVendor });
                hasValidMatch = true;
              } 
              // Priority 2: Publisher match
              else if (vendor === normalizedPublisher || normalizedPublisher.includes(vendor) || vendor.includes(normalizedPublisher)) {
                vendorMatches.set(vendor, { priority: 2, original: originalVendor });
                hasValidMatch = true;
              }
              // Priority 3: First word match (only for vendors)
              else if (nameParts.length > 0 && vendor === nameParts[0]) {
                vendorMatches.set(vendor, { priority: 3, original: originalVendor });
                hasValidMatch = true;
              }
              // Add short name part matches for vendors
              else if (shortNameParts.length > 0) {
                for (let i = 0; i < shortNameParts.length; i++) {
                  if (vendor === shortNameParts[i]) {
                    vendorMatches.set(vendor, { priority: 4 + i, original: originalVendor });
                    hasValidMatch = true;
                    break;
                  }
                }
              }
            }
  
            // PRODUCT MATCHING - with combinations
            if (product && product !== 'n/a') {
              // Priority 1: Exact full name match
              if (product === normalizedName) {
                productMatches.set(product, { priority: 1, original: originalProduct });
                hasValidMatch = true;
              } 
              // Priority 2: Check for exact match with any of the word combinations
              else {
                // First check 3-word combinations
                let matched = false;
                for (const combo of comboParts.filter(c => c.split(' ').length === 3)) {
                  if (product === combo) {
                    productMatches.set(product, { priority: 2, original: originalProduct });
                    hasValidMatch = true;
                    matched = true;
                    break;
                  }
                }
                
                // Then check 2-word combinations if not matched yet
                if (!matched) {
                  for (const combo of comboParts.filter(c => c.split(' ').length === 2)) {
                    if (product === combo) {
                      productMatches.set(product, { priority: 3, original: originalProduct });
                      hasValidMatch = true;
                      matched = true;
                      break;
                    }
                  }
                }
                
                // Then check standard words
                if (!matched) {
                  for (let i = 0; i < nameParts.length; i++) {
                    if (product === nameParts[i]) {
                      productMatches.set(product, { priority: 4 + i, original: originalProduct });
                      hasValidMatch = true;
                      matched = true;
                      break;
                    }
                  }
                }
                
                // check short words (R, etc)
                if (!matched) {
                  for (let i = 0; i < shortNameParts.length; i++) {
                    if (product === shortNameParts[i]) {
                      productMatches.set(product, { priority: 4 + nameParts.length + i, original: originalProduct });
                      hasValidMatch = true;
                      matched = true;
                      break;
                    }
                  }
                }
              }
            }
          }
        }
  
        if (Array.isArray(cve.vulnerable_cpe)) {
          for (const cpeString of cve.vulnerable_cpe) {
            const parts = cpeString.split(':');
            if (parts.length >= 5) {
              const vendor = parts[3].toLowerCase();
              const product = parts[4].toLowerCase();
              const originalVendor = parts[3];
              const originalProduct = parts[4];
  
              // VENDOR MATCHING
              if (vendor && vendor !== '*' && vendor !== '-' && vendor !== 'n/a') {
                // Priority 1: Exact full name match
                if (vendor === normalizedName) {
                  vendorMatches.set(vendor, { priority: 1, original: originalVendor });
                  hasValidMatch = true;
                } 
                // Priority 2: Publisher match
                else if (vendor === normalizedPublisher || normalizedPublisher.includes(vendor) || vendor.includes(normalizedPublisher)) {
                  vendorMatches.set(vendor, { priority: 2, original: originalVendor });
                  hasValidMatch = true;
                }
                // Priority 3: First word match (only for vendors)
                else if (nameParts.length > 0 && vendor === nameParts[0]) {
                  vendorMatches.set(vendor, { priority: 3, original: originalVendor });
                  hasValidMatch = true;
                }
                // Add short name part matches for vendors
                else if (shortNameParts.length > 0) {
                  for (let i = 0; i < shortNameParts.length; i++) {
                    if (vendor === shortNameParts[i]) {
                      vendorMatches.set(vendor, { priority: 4 + i, original: originalVendor });
                      hasValidMatch = true;
                      break;
                    }
                  }
                }
              }
  
              // PRODUCT MATCHING - with combinations
              if (product && product !== '*' && product !== '-' && product !== 'n/a') {
                // Priority 1: Exact full name match
                if (product === normalizedName) {
                  productMatches.set(product, { priority: 1, original: originalProduct });
                  hasValidMatch = true;
                } 
                // Priority 2: Check for exact match with any of the word combinations
                else {
                  // First check 3-word combinations
                  let matched = false;
                  for (const combo of comboParts.filter(c => c.split(' ').length === 3)) {
                    if (product === combo) {
                      productMatches.set(product, { priority: 2, original: originalProduct });
                      hasValidMatch = true;
                      matched = true;
                      break;
                    }
                  }
                  
                  // Then check 2-word combinations if not matched yet
                  if (!matched) {
                    for (const combo of comboParts.filter(c => c.split(' ').length === 2)) {
                      if (product === combo) {
                        productMatches.set(product, { priority: 3, original: originalProduct });
                        hasValidMatch = true;
                        matched = true;
                        break;
                      }
                    }
                  }
                  
                  // Then check standard words
                  if (!matched) {
                    for (let i = 0; i < nameParts.length; i++) {
                      if (product === nameParts[i]) {
                        productMatches.set(product, { priority: 4 + i, original: originalProduct });
                        hasValidMatch = true;
                        matched = true;
                        break;
                      }
                    }
                  }
                  
                  // Finally check short words (R, etc)
                  if (!matched) {
                    for (let i = 0; i < shortNameParts.length; i++) {
                      if (product === shortNameParts[i]) {
                        productMatches.set(product, { priority: 4 + nameParts.length + i, original: originalProduct });
                        hasValidMatch = true;
                        matched = true;
                        break;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
  
      // Convert from maps and sort by priority
      const sortedVendors = Array.from(vendorMatches.entries())
        .sort((a, b) => a[1].priority - b[1].priority)
        .map(([_, info]) => info.original)
        .slice(0, 3); // Limit to 3 vendors
      
      const sortedProducts = Array.from(productMatches.entries())
        .sort((a, b) => a[1].priority - b[1].priority)
        .map(([_, info]) => info.original)
        .slice(0, 3); // Limit to 3 products
  
      console.log(`Matched for "${originalName}": Vendors → ${JSON.stringify(sortedVendors)}`);
      console.log(`Matched for "${originalName}": Products → ${JSON.stringify(sortedProducts)}`);
  
      if (!hasValidMatch) return null;
  
      // Store the match results in the cache collection
      await cacheCollection.updateOne(
        { normalized_name: normalizedName },
        { 
          $set: {
            original_name: originalName,
            normalized_name: normalizedName,
            matched_vendors: sortedVendors,
            matched_products: sortedProducts,
            cve_count: cveMatches.length,
            last_updated: new Date()
          }
        },
        { upsert: true }
      );
  
      return {
        software_name: software.name,
        software_version: software.version || "Unknown",
        software_publisher: software.publisher || "Unknown",
        cve_count: cveMatches.length,
        matched_vendors: sortedVendors,
        matched_products: sortedProducts,
        cached: false
      };
    } catch (error) {
      console.error(`Error processing software ${software.name}: ${error.message}`);
      return null;
    }
  }
  
  // Process entity for CVE details
  async function processEntity(db, entityName, entityType, vulnerabilityCollection) {
    try {
      // Check if this name has already been processed
      if (!entityName) return null;
      
      console.log(`Processing entity: ${entityName} (${entityType})`);
  
      // Different capitalization patterns to try
      const capitalizations = [
        entityName, // Original
        entityName.charAt(0).toUpperCase() + entityName.slice(1), // First letter capitalized
        entityName.toUpperCase(), // All uppercase
      ];
      
      // For multi-word names, try capitalizing first letter of each word
      if (entityName.includes(' ')) {
        const words = entityName.split(' ');
        const titleCase = words.map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
        capitalizations.push(titleCase);
      }
  
      // Try each capitalization pattern
      for (const capitalization of capitalizations) {
        const cves = await vulnerabilityCollection.find({
          $or: [
            { "cpe.vendor": capitalization },
            { "cpe.product": capitalization },
            { "vulnerable_cpe": { $regex: capitalization, $options: "i" } }
          ]
        })
        .project({
          cve_id: 1,
          description: 1,
          cvss_score: 1,
          cvss_metrics: 1,
          epss: 1,
          published_at: 1,
          is_exploited: 1
        })
        .limit(100)  // Limit to avoid excessive results
        .toArray();
  
        if (cves.length > 0) {
          console.log(`Found ${cves.length} CVEs for "${capitalization}"`);
          
          return {
            type: entityType,
            name: capitalization,
            cves: cves.map(cve => {
              // Handle published_at date
              let publishedDate = 'Unknown';
              if (cve.published_at) {
                if (cve.published_at.$date) {
                  publishedDate = new Date(cve.published_at.$date).toISOString().split('T')[0];
                } else if (typeof cve.published_at === 'string') {
                  publishedDate = new Date(cve.published_at).toISOString().split('T')[0];
                } else if (cve.published_at instanceof Date) {
                  publishedDate = cve.published_at.toISOString().split('T')[0];
                }
              }
              
              return {
                cve_id: cve.cve_id,
                description: cve.description,
                cvss_score: cve.cvss_score || 
                          (cve.cvss_metrics?.cvss3?.score || 
                           cve.cvss_metrics?.cvss2?.score || 'Unknown'),
                epss_score: cve.epss?.epss_score || 'Unknown',
                epss_percentile: cve.epss?.epss_percentile || 'Unknown',
                published_date: publishedDate,
                is_exploited: cve.is_exploited === true ? 'Yes' : 'No'
              };
            })
          };
        }
      }
      
      // No CVEs found for any capitalization
      return null;
    } catch (error) {
      console.error(`Error processing entity ${entityName}: ${error.message}`);
      return null;
    }
  }
  
  // Main worker task handler
  async function runWorkerTask() {
    try {
      const { task, taskType, dbInfo } = workerData;
      
      // Connect to the database - create a new connection for each worker
      const client = new MongoClient(dbInfo.uri, dbInfo.options);
      await client.connect();
      const db = client.db(dbInfo.dbName);
      
      let result;
      
      // Handle different task types
      if (taskType === 'processSoftware') {
        const vulnerabilityCollection = db.collection('unified_cves');
        const cacheCollection = db.collection('cve_match_cache');
        result = await processSoftware(db, task.software, vulnerabilityCollection, cacheCollection);
      } 
      else if (taskType === 'processEntity') {
        const vulnerabilityCollection = db.collection('unified_cves');
        result = await processEntity(db, task.name, task.type, vulnerabilityCollection);
      }
      
      // Close the database connection when done
      await client.close();
      
      // Send result back to parent
      parentPort.postMessage({ success: true, result });
    } catch (error) {
      // Handle errors
      parentPort.postMessage({ success: false, error: error.message });
    }
}

// Start the worker
runWorkerTask();