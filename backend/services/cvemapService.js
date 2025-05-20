//services/cvemapServices.js
const fs = require("fs").promises;
const path = require("path");
const { spawn } = require("child_process");
const { createCVEMapModel } = require("../models/CVE");
const logger = require("../logger");

const minesPath = path.join(__dirname, "../../../mines");

async function processChangedFilesCvemap(inputFilePath, db) {
  const outputFilePath = path.join(path.dirname(inputFilePath), "output.json"); // Change the output file name as needed
  const scriptPath = "./utils/cvemap-worker.sh"; // Specify the path to your shell script

  // Execute the shell script with the input file path
  try {
    await new Promise((resolve, reject) => {
      logger.info("Running shell script");

      const child = spawn("bash", [scriptPath, inputFilePath]);

      let stdout = "";
      let stderr = "";

      // Capture standard output
      child.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      // Capture standard error
      child.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      // Handle process exit
      child.on("exit", (code) => {
        if (code !== 0) {
          logger.info(`Shell script Exit Code:: ${code}`);
          logger.error(`Error executing script: ${stderr}`);
          return reject(`Error executing script: ${stderr}`);
        }
        resolve(stdout);
      });

      // Handle errors in spawning the process
      child.on("error", (err) => {
        logger.error(`Failed to start script: ${err.message}`);
        reject(`Failed to start script: ${err.message}`);
      });
    });

    // Read the generated output file
    logger.info(`Reading File: ${outputFilePath}`);
    const data = await fs.readFile(outputFilePath, "utf8");
    logger.info(`Parsing Json from ${outputFilePath}`);
    const jsonArray = JSON.parse(data);

    // Sort the array by published_at date in descending order (latest to oldest)
    // jsonArray.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));

    const cveMapCollection = createCVEMapModel(db);

    logger.info("Inserting Entries into the database");
    // Insert entries into the database
    const insertPromises = jsonArray.map((item) =>
      insertCVEMapEntry(item, cveMapCollection),
    );
    await Promise.all(insertPromises);

    logger.info(
      "CVE data successfully inserted from the generated output file.",
    );
  } catch (error) {
    logger.error("Error processing CVE file:");
    logger.error(error);
  }
}
async function parseCVEMapData(db) {
  const cveMapCollection = createCVEMapModel(db);

  // const filePath = path.join(minesPath, file);
  const filePath = path.join(minesPath, "2024.json");
  const data = await fs.readFile(filePath, "utf8");
  const jsonArray = JSON.parse(data);

  // Sort the array by published_at date in descending order (latest to oldest)
  //jsonArray.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));

  logger.info("Inserting CVEMap 2024 data now ...");
  for (const item of jsonArray) {
    await insertCVEMapEntry(item, cveMapCollection);
  }

  logger.info(
    "CVEMap data for 2024 successfully inserted from latest to oldest.",
  );
}

/**
 * Insert a single CVEMap entry into the collection.
 * @param {Object} item - The CVEMap entry to insert.
 * @param {Object} cveMapCollection - The MongoDB collection to insert into.
 */
async function insertCVEMapEntry(item, cveMapCollection) {
  const cveId = item.cve_id;
  const description = item.cve_description || "No description provided";
  const source = "CVEMap";

  // Extract CVSS score, EPSS score, and other fields
  // const cvssScore = item.cvss_score || null;
  // const cvssMetrics = item.cvss_metrics || null; // Keep the CVSS metrics object
  // const epssScore = item.epss?.epss_score || null;
  // const epssPercentile = item.epss?.epss_percentile || null;
  const hackeroneLink = item.hackerone || null;

  // Extract weaknesses if available
  const weaknesses = item.weaknesses || [];

  // Ensure vulnerable_cpe is an array before mapping
  const vulnerableCPE = Array.isArray(item.vulnerable_cpe)
    ? item.vulnerable_cpe
    : [];
  const cpeData = vulnerableCPE.map((aff) => ({
    cpe: aff,
    vendor: item.cpe?.vendor || "Unknown Vendor",
    product: item.cpe?.product || "Unknown Product",
  }));

  // Insert the CVEMap entry
  await cveMapCollection.updateOne(
    { cve_id: cveId },
    {
      $set: {
        age_in_days: item.age_in_days || null,
        assignee: item.assignee || null,
        cpe_data: cpeData,
        cve_id: cveId,
        cvss_score: item.cvss_score || null,
        cvss_metrics: item.cvss_metrics || null, // Keep the CVSS metrics object ,
        description: item.description,
        epss: { epss_score: item.epss?.epss_score || null , epss_percentile: item.epss?.epss_percentile || null , },
        hackerone: item.hackerone || null,
        is_exploited: item.is_exploited || false,
        is_oss: item.is_oss || false,
        is_poc: item.is_poc || false,
        is_remote: item.is_remote || false,
        is_template: item.is_template || false,
        kev: item.kev || null , //known exploited vulnerability
        nuclei_templates: item.nuclei_templates || [] , // links to nuclei templates
        oss: item.oss || null , //oss
        patch_url: item.patch_url || [] ,
        poc: item.poc || [],
        published_at: new Date(item.published_at),
        references: item.reference || [],
        severity: item.severity,
        source,
        tag: "R",
        updated_at: new Date(item.updated_at),
        vendor_advisory: item.vendor_advisory || null,
        vuln_status: item.vuln_status || null,
        weaknesses,
      },
    },
    { upsert: true }, // Insert if it doesn't exist
  );
}

module.exports = {
  parseCVEMapData,
  processChangedFilesCvemap,
};

