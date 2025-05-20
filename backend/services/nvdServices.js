const fs = require("fs").promises;
const path = require("path");
const axios = require("axios");
const zlib = require("zlib"); // Make sure to import zlib
const logger = require("../logger");

const { createnvdModel } = require("../models/CVE");

const nvdPath = path.join(__dirname, process.env.ASSETS, "../nvd"); // Path to NVD data files

async function parseNVDData(db) {
  const nvdCollection = createnvdModel(db);

  // Check if the collection already has data
  const count = await nvdCollection.countDocuments();

  if (count === 0) {
    logger.info("NVD collection is empty. Initial parsing will occur.");
    await initialNVDParsing(nvdCollection);
  } else {
    logger.info("NVD collection already has data. Handling modified NVD data.");
    await handleModifiedNVDData(nvdCollection);
  }
}

async function initialNVDParsing(nvdCollection) {
  // Your logic for initial parsing of NVD data (not modified)
  const filePath = path.join(nvdPath, "nvdcve-1.1-2024.json"); // Change to the correct file name
  const data = await fs.readFile(filePath, "utf8");
  const parsedData = JSON.parse(data);
  const jsonArray = parsedData.CVE_Items;

  if (!Array.isArray(jsonArray)) {
    throw new Error("Expected an array of CVE Items");
  }

  // Sort the array by published_at date in descending order (latest to oldest)
  jsonArray.sort(
    (a, b) => new Date(b.publishedDate) - new Date(a.publishedDate),
  );

  for (const item of jsonArray) {
    await insertNVDEntry(item, nvdCollection);
  }

  logger.info(
    "Initial NVD data for 2024 successfully inserted from latest to oldest.",
  );
}

async function handleModifiedNVDData(nvdCollection) {
  const modifiedFilePath = path.join(nvdPath, "nvdcve-1.1-modified.json"); // Path to modified NVD data file

  // Delete any existing modified data file if it exists
  try {
    await fs.unlink(modifiedFilePath);
    logger.info("Deleted existing modified NVD data file.");
  } catch (error) {
    if (error.code !== "ENOENT") {
      logger.error("Error deleting existing modified NVD data file:");
      logger.error(error);
    } else {
      logger.info("No existing modified NVD data file found to delete.");
    }
  }

  const url =
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz";

  try {
    const response = await axios.get(url, { responseType: "arraybuffer" });
    const gzFilePath = path.join(nvdPath, "nvdcve-1.1-modified.json.gz");

    // Save the downloaded file
    await fs.writeFile(gzFilePath, response.data);
    logger.info("Downloaded modified NVD data.");

    // Unzip the downloaded file
    await unzipFile(gzFilePath, modifiedFilePath);

    // Proceed with parsing the unzipped modified data
    const data = await fs.readFile(modifiedFilePath, "utf8");
    const parsedData = JSON.parse(data);

    await processNVDJson(parsedData, nvdCollection);

    logger.info("Modified NVD data successfully inserted.");
  } catch (error) {
    logger.error("Error handling modified NVD data:");
    logger.error(error);
  }
}

async function unzipFile(gzFilePath, outputFilePath) {
  const fileContent = await fs.readFile(gzFilePath);

  const unzippedContent = await new Promise((resolve, reject) => {
    zlib.gunzip(fileContent, (err, buffer) => {
      if (err) {
        reject(err);
      } else {
        resolve(buffer);
      }
    });
  });

  // Save the unzipped file
  await fs.writeFile(outputFilePath, unzippedContent);
  logger.info(`Unzipped modified data saved to ${outputFilePath}`);
}

async function processNVDJson(parsedData, nvdCollection) {
  const jsonArray = parsedData.CVE_Items;

  if (!Array.isArray(jsonArray)) {
    throw new Error("Expected an array of CVE Items");
  }

  // Sort the array by published_at date in descending order (latest to oldest)
  jsonArray.sort(
    (a, b) => new Date(b.publishedDate) - new Date(a.publishedDate),
  );

  for (const item of jsonArray) {
    await insertNVDEntry(item, nvdCollection);
  }

  logger.info("NVD data successfully inserted from latest to oldest.");
}
async function insertNVDEntry(item, nvdCollection) {
  const cveId = item.cve.CVE_data_meta.ID;
  const description =
    item.cve.description.description_data[0]?.value ||
    "No description provided";
  const source = "NVD";

  // CVSS v3 base score and metrics (V3 is more recent than V2)
  const cvssScore = item.impact?.baseMetricV3?.cvssV3?.baseScore || null;
  const cvssMetrics = item.impact?.baseMetricV3?.cvssV3 || null;

  // CVSS v2 metrics if V3 is not available
  const cvssScoreV2 = item.impact?.baseMetricV2?.cvssV2?.baseScore || null;
  const cvssMetricsV2 = item.impact?.baseMetricV2?.cvssV2 || null;

  // Weaknesses (CWE information)
  const weaknesses =
    item.cve.problemtype.problemtype_data[0]?.description.map((w) => ({
      cwe_id: w.value,
      cwe_name: w.value, // The description is sometimes identical to the value
    })) || [];

  // References (URLs for more details)
  const references =
    item.cve.references.reference_data || [];

  // Initialize variables
  const vendor_advisory = [];
  const patch_url = [];

  // Iterate through the reference data
  references.forEach(reference => {
    // Check if the tags include "Vendor Advisory"
    if (reference.tags.includes("Vendor Advisory")) {
      vendor_advisory.push(reference.url);
    }
    // Check if the tags include "Patch"
    if (reference.tags.includes("Patch")) {
      patch_url.push(reference.url);
    }
  });


  // CPE data (Common Platform Enumeration) - List of affected software, hardware, etc.
  const vulnerableCPE =
    item.configurations?.nodes
      ?.map((node) => node.cpe_match?.map((cpe) => cpe.cpe23Uri))
      .flat() || [];

    function IterarteConfig(nodes, cpe_data){
      //loop nodes
      try { 
      if ( nodes && nodes.length > 0 ){
        for ( node of nodes){
          processEachConfig(node, cpe_data);
        }
      }    
      } catch (err) {
        console.log(item.cve.CVE_data_meta.ID);
        console.log(err);
      }
    }

    function processEachConfig(node, cpeArray){
      //operator check
      if ( node.operator === 'OR' ){
        // console.log("OR");
        for (cpe of node.cpe_match){
          const parsedCPE = parseVulnerableCpe(cpe.cpe23Uri);
          parsedCPE.versions = [Object.assign({}, parsedCPE.versions, cpe) ]; 
          cpeArray.push(parsedCPE);
        }
      } else {
        // console.log("AND");

        let affected = [];
        if (node.children[0]){
          processEachConfig(node.children[0], affected);
        }

        let runningWith = [];
        // if (node.children[1]){
        //   processEachConfig(node.children[1], runningWith);
        // }

        for( cpe of affected ){
          cpe.runningWith = runningWith;
          cpeArray.push(cpe);
        }
      }
    }

    function parseVulnerableCpe(cpe) {

      const parts = cpe.split(':');
      return {
               // cpe_version: formatName(parts[1]),
               product_code: formatName(parts[2]),
               vendor: formatName(parts[3]),
               product: formatName(parts[4]),
               versions: { "versionStartIncluding": formatName(parts[5]) },
               update: formatName(parts[6]),
               // edition: formatName(parts[7]),
               // lang: formatName(parts[8]),
               // sw_edition: formatName(parts[9]),
               // target_sw: formatName(parts[10]),
               // target_hw: formatName(parts[11]),
               // other: formatName(parts[12])
      };
    }

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

    const cpe_data = [];
    IterarteConfig(item.configurations?.nodes, cpe_data);



  // Other impact information
  const isExploited = !!item.impact?.baseMetricV3?.exploitabilityScore;
  const severity = item.impact?.baseMetricV3?.cvssV3?.baseSeverity || "Unknown";

  // Published and updated dates
  const publishedAt = new Date(item.publishedDate);
  const updatedAt = new Date(item.lastModifiedDate);

  // Insert the NVD entry
  await nvdCollection.updateOne(
    { _id: cveId },
    {
      $set: {
        cpe_data,
    cve_id: cveId,
    cvss_metrics: cvssMetrics,
    cvss_metrics_v2: cvssMetricsV2,
    cvss_score: cvssScore,
    cvss_score_v2: cvssScoreV2,
    description,
    is_exploited: isExploited,
    patch_url,
    published_at: publishedAt,
    references,
    severity,
    source,
    tag: "R", // Mark newly added or modified items as 'R' (Required for unified collection)
    updated_at: updatedAt,
    vendor_advisory,
    vulnerable_cpe: vulnerableCPE,
    weaknesses,
      },
    },
    { upsert: true }, // Insert if it doesn't exist, update if it does
  );
}

module.exports = {
  parseNVDData,
};
