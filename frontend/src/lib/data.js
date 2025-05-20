export const vendor_year = [
    {
      "cve_id": "CVE-2024-1234",
      "description": "Sensitive information manipulation due to improper authorization. The following products are affected: Acronis Cyber Protect 16 (Linux, Windows) before build 38690.",
      "published_at": "2024-03-15T10:30:00Z",
      "updated_at": "2024-03-15T10:30:00Z",
      "cvss_score": "9.1",
      "epss_score": "N/A",
      "source": "Acronis International GmbH"
    },
    {
      "cve_id": "CVE-2024-1235",
      "description": "Sensitive information manipulation due to improper authorization. The following products are affected: Acronis Cyber Protect 16 (Linux, Windows) before build 38690.",
      "published_at": "2024-03-15T10:30:00Z",
      "updated_at": "2024-03-15T10:30:00Z",
      "cvss_score": "N/A",
      "epss_score": "N/A",
      "source": "Acronis International GmbH"
    },
    {
      "cve_id": "CVE-2024-1236",
      "description": "Sensitive information manipulation due to improper authorization. The following products are affected: Acronis Cyber Protect 16 (Linux, Windows) before build 38690.",
      "published_at": "2024-03-15T10:30:00Z",
      "updated_at": "2024-03-15T10:30:00Z",
      "cvss_score": "3.2",
      "epss_score": "5.1",
      "source": "Acronis International GmbH"
    },
    {
      "cve_id": "CVE-2024-1237",
      "description": "Sensitive information manipulation due to improper authorization. The following products are affected: Acronis Cyber Protect 16 (Linux, Windows) before build 38690.",
      "published_at": "2024-03-15T10:30:00Z",
      "updated_at": "2024-03-15T10:30:00Z",
      "cvss_score": "9.1",
      "epss_score": "N/A",
      "source": "Acronis International GmbH"
    },
  ]


export const CveDetails = {
  "cve_id": "CVE-2024-8991",
  "description": "Sensitive information manipulation due to improper authorization. The following products are affected: Acronis Cyber Protect 16 (Linux, Windows) before build 38690.",
  "cvss_score": 7.5,
  "epss_score": 5.1,
  "published_at": "2024-03-15T10:30:00Z",
  "updated_at": "2024-03-16T14:20:00Z",
  "source": "Acronis International GmbH"
}

export const Cvss_Stats = {
  "scoreRanges": {
    "0-1": 50,
    "1-2": 120,
    "2-3": 200,
    "3-4": 350,
    "4-5": 400,
    "5-6": 600,
    "6-7": 450,
    "7-8": 300,
    "8-9": 200,
    "9+": 100
  },
  "totalCount": 2770,
  "weightedAverage": 5.8
}

export const RadialGraphData = {
  "newAndUpdatedCVEs": {
    "createdSinceYesterday": 25,
    "updatedSinceYesterday": 45,
    "createdLast7Days": 150,
    "updatedLast7Days": 280,
    "createdLast30Days": 620,
    "updatedLast30Days": 980
  },
  "exploitedStats": {
    "sinceYesterday": 5,
    "last7Days": 35,
    "last30Days": 120
  }
}

  export const vendorStatsData = [
    {
      "_id": 2024,
      "vulnerabilities": {
        "CWE-79": 15,
        "CWE-89": 8,
        "CWE-787": 12
      }
    },
    {
      "_id": 2023,
      "vulnerabilities": {
        "CWE-79": 25,
        "CWE-89": 10,
        "CWE-787": 18
      }
    },
    {
      "_id": 2022,
      "vulnerabilities": {
        "CWE-79": 25,
        "CWE-89": 1,
        "CWE-787": 18
      }
    },
    {
      "_id": 2021,
      "vulnerabilities": {
        "CWE-79": 25,
        "CWE-89": 10,
        "CWE-787": 1
      }
    },
    {
      "_id": 2020,
      "vulnerabilities": {
        "CWE-79": 2,
        "CWE-89": 10,
        "CWE-787": 18
      }
    },
    {
      "_id": 2019,
      "vulnerabilities": {
        "CWE-79": 5,
        "CWE-89": 0,
        "CWE-787": 18
      }
    },
    {
      "_id": 2018,
      "vulnerabilities": {
        "CWE-79": 42,
        "CWE-89": 12,
        "CWE-787": 9
      }
    },
    {
      "_id": 2017,
      "vulnerabilities": {
        "CWE-79": 25,
        "CWE-89": 10,
        "CWE-787": 18
      }
    },
    {
      "_id": 2016,
      "vulnerabilities": {
        "CWE-79": 25,
        "CWE-89": 10,
        "CWE-787": 18
      }
    },
    {
      "_id": 2015,
      "vulnerabilities": {
        "CWE-79": 25,
        "CWE-89": 10,
        "CWE-787": 18
      }
    },
    {
      "_id": 2014,
      "vulnerabilities": {
        "CWE-79": 25,
        "CWE-89": 10,
        "CWE-787": 18
      }
    },
    {
      "_id": 2013,
      "vulnerabilities": {
        "CWE-79": 25,
        "CWE-89": 10,
        "CWE-787": 18
      }
    }
  ]


  //inorder to use sample data
 export const sampleCVEData = {
  "_id": "CVE-2025-24200",
  "cve_id": "CVE-2025-24200",
  "description": "An authorization issue was addressed with improved state management. This issue is fixed in iPadOS 17.7.5, iOS 18.3.1 and iPadOS 18.3.1. A physical attack may disable USB Restricted Mode on a locked device. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.",
  "severity": "MEDIUM",
  "cvss_score": 6.1,
  "cvss_metrics": {
    "version": "3.1",
    "vectorString": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "attackVector": "PHYSICAL",
    "attackComplexity": "LOW",
    "privilegesRequired": "NONE",
    "userInteraction": "NONE",
    "scope": "UNCHANGED",
    "confidentialityImpact": "HIGH",
    "integrityImpact": "HIGH",
    "availabilityImpact": "NONE",
    "baseScore": 6.1,
    "baseSeverity": "MEDIUM"
  },
  "weaknesses": [
    {
      "cwe_id": "Unknown CWE",
      "description": "A physical attack may disable USB Restricted Mode on a locked device. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals."
    }
  ],
  "epss": null,
  "cpe": [
    {
      "vendor": "Apple",
      "product": "iPadOS",
      "versions": [
        {
          "version": "unspecified",
          "status": "affected",
          "lessThan": "17.7",
          "versionType": "custom"
        }
      ]
    },
    {
      "vendor": "Apple",
      "product": "iOS and iPadOS",
      "versions": [
        {
          "version": "unspecified",
          "status": "affected",
          "lessThan": "18.3",
          "versionType": "custom"
        }
      ]
    }
  ],
  "references": [],
  "vendor_advisory": [
    "https://support.apple.com/en-us/122173",
    "https://support.apple.com/en-us/122174"
  ],
  "is_template": false,
  "is_exploited": true,
  "assignee": null,
  "published_at": "2025-02-10T19:04:45.242Z",
  "updated_at": "2025-03-20T14:31:13.832Z",
  "hackerone": null,
  "age_in_days": null,
  "vuln_status": null,
  "is_poc": false,
  "is_remote": false,
  "is_oss": false,
  "vulnerable_cpe": [
    "cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*",
    "cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*",
    "cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*"
  ],
  "patch_url": [],
  "kev": null,
  "nuclei_templates": null,
  "oss": null,
  "poc": null,
  "shodan": null,
  "source": "Unified",
  "tag": "N"
};
