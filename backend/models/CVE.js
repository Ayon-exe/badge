const { ObjectId } = require('mongodb');

const createCVEModel = (db) => {
    return db.collection('cves');
};

const createCVEMapModel = (db) => {
    return db.collection('cvemap');
};

const createnvdModel = (db) => {
    return db.collection('nvd');
};
const createUnifiedModel = (db) => {
    return db.collection('unified_cves');
};

const createBoxDataModel = (db) => {
    return db.collection('boxData');
};

const createCvssDataModel = (db) => {
    return db.collection('cvss');
};

const createCweDataModel = (db) => {
    return db.collection('cwe');
};

const createExploitedDataModel = (db) => {
    return db.collection('exploited');
};

const createFixesDataModel = (db) => {
    return db.collection('fixes');
};

const createTopVendorsDataModel = (db) => {
    return db.collection('top_vendors');
};

const createCveStatsDataModel = (db) => {
    return db.collection('cve_stats');
};

const cveSchema = {
    _id: ObjectId,
    cve_id: { type: String, required: true },  // e.g., CVE-2024-0001
    description: { type: String, required: true },
    severity: { type: String },  // e.g., 'critical', 'high'
    cvss_score: { type: Number },
    cvss_metrics: { type: Object },  // Nested CVSS metrics
    weaknesses: { type: [Object], default: [] },  // CWE or weakness information
    epss: { type: Object, default: null },  // EPSS score data
    cpe: { type: Object, default: null },  // CPE data
    references: { type: [String], default: [] },  // External references
    vendor_advisory: { type: String, default: null },
    is_template: { type: Boolean, default: false },
    is_exploited: { type: Boolean, default: false },
    assignee: { type: String, default: null },
    published_at: { type: Date, default: null },
    updated_at: { type: Date, default: null },
    hackerone: { type: Object, default: null },  // HackerOne rank, etc.
    age_in_days: { type: Number, default: null },
    vuln_status: { type: String, default: null },  // Vulnerability status (e.g., confirmed)
    is_poc: { type: Boolean, default: false },  // Proof of concept exists?
    is_remote: { type: Boolean, default: false },  // Remote exploitability
    is_oss: { type: Boolean, default: false },  // Open source software?
    vulnerable_cpe: { type: [String], default: [] },  // List of vulnerable CPEs
    source: { type: String, default: 'Unknown' },  // Data source (MITRE, NVD, CVEMap)
    tag: { type: String, default: 'R' }  ,// Tag to indicate if data needs to be added to the unified DB
    poc: { type: [Object], default: [] }
};

module.exports = {
  createCVEMapModel,
  createCVEModel,
  createnvdModel,
  createUnifiedModel,
  createBoxDataModel,
  createCweDataModel,
  createCvssDataModel,
  createExploitedDataModel,
  createFixesDataModel,
  createTopVendorsDataModel,
  createCveStatsDataModel,
  cveSchema
};




// const { ObjectId } = require('mongodb');

// const createCVEModel = (db) => {
//     return db.collection('cves');
// };

// const createCVEMapModel = (db) => {
//     return db.collection('cvemap');
// };

// const cveSchema = {
//     _id: ObjectId,
//     cve_id: { type: String, required: true },  // e.g., CVE-2024-0001
//     description: { type: String, required: true },
//     severity: { type: String },  // e.g., 'critical', 'high'
//     cvss_score: { type: Number },
//     cvss_metrics: { type: Object },  // Nested CVSS metrics
//     weaknesses: { type: [Object], default: [] },  // CWE or weakness information
//     epss: { type: Object, default: null },  // EPSS score data
//     cpe: { type: Object, default: null },  // CPE data
//     references: { type: [String], default: [] },  // External references
//     vendor_advisory: { type: String, default: null },
//     is_template: { type: Boolean, default: false },
//     is_exploited: { type: Boolean, default: false },
//     assignee: { type: String, default: null },
//     published_at: { type: Date, default: null },
//     updated_at: { type: Date, default: null },
//     hackerone: { type: Object, default: null },  // HackerOne rank, etc.
//     age_in_days: { type: Number, default: null },
//     vuln_status: { type: String, default: null },  // Vulnerability status (e.g., confirmed)
//     is_poc: { type: Boolean, default: false },  // Proof of concept exists?
//     is_remote: { type: Boolean, default: false },  // Remote exploitability
//     is_oss: { type: Boolean, default: false },  // Open source software?
//     vulnerable_cpe: { type: [String], default: [] },  // List of vulnerable CPEs
//     source: { type: String, default: 'Unknown' }  // Data source (MITRE, NVD, CVEMap)
// };

// module.exports = {
//     createCVEMapModel,
//     createCVEModel,
//     cveSchema
// };




