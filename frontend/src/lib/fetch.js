import axios from "axios";

// Vendor List by Date
export async function getVendorByDate(vendor, year, page, limit) {
  const response = await axios.get(
    `${process.env.SERVER_URL}/api/cve/vendor/${vendor}/year/${year}?page=${page}&limit=${limit}`
  );
  console.log(response);
  return response.data;
}

export const getProductsAndVendorsWatchlist = async () => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    throw new Error("No authentication token found");
  }

  // Add a timestamp to prevent browser caching
  const timestamp = new Date().getTime();

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/watchlist/products-vendors`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        // Add a timeout to abort requests that take too long
        timeout: 10000,
      }
    );
    return response.data;
  } catch (err) {
    console.error("Error fetching Products and Vendors Watchlist:", err);
    throw new Error("Failed to fetch Products and Vendors Watchlist");
  }
};

// Fetch the user's watchlist items data
export const getWatchlistItemStats = async () => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    throw new Error("No authentication token found");
  }

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/watchlist-cve-stats`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    console.log(response.data);
    return response.data;
  } catch (err) {
    console.error(err);
    throw new Error("Failed to fetch watchlist");
  }
};

// Fetch the user's watchlist
export const getWatchlist = async () => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    throw new Error("No authentication token found");
  }

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/watchlist`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    return response.data;
  } catch (err) {
    console.error(err);
    throw new Error("Failed to fetch watchlist");
  }
};

// Add a helper function to filter the already fetched CVE data locally
export const filterCvesLocal = (cvesData, filters) => {
  return cvesData.filter((cve) => {
    let include = true;
    if (filters.vendor) {
      // Assuming the vendor is stored under cve.cpe.vendor
      include =
        include &&
        cve.cpe.vendor.toLowerCase().includes(filters.vendor.toLowerCase());
    }
    if (filters.product) {
      // Assuming the product is stored under cve.cpe.product
      include =
        include &&
        cve.cpe.product.toLowerCase().includes(filters.product.toLowerCase());
    }
    // add more filter conditions as needed
    return include;
  });
};

export const getFilteredCves = async (filters) => {
  try {
    const response = await axios.post(
      `${process.env.SERVER_URL}/api/cve/filter`,
      { filters }
    );
    return response.data;
  } catch (err) {
    console.error(err);
    throw new Error("Failed to filter CVEs");
  }
};

// CVE by CVE id
export const getCvebyId = async (cveid) => {
  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/cveid/${cveid}`
    );
    return response.data;
  } catch (err) {
    console.error(err);
    return null; // Return null in case of an error to avoid undefined data
  }
};

// // Vendor Statistics Data
// export async function getVendorStatsData(vendor) {
//   try {
//     const response = await fetch(
//       `${process.env.SERVER_URL}/api/cve/statistics/${vendor}`
//     );

//     if (!response.ok) {
//       throw new Error("Failed to fetch vendor statistics");
//     }

//     return response.json();
//   } catch (error) {
//     console.error("Error fetching vendor stats:", error);
//     return [];
//   }
// }

// Vendor Statistics Data
export const getVendorStatsData = async (vendor) => {
  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/vendor/${vendor}/stats`
    );
    return response.data;
  } catch (err) {
    console.error(err);
    throw new Error("Failed to fetch vendor statistics");
  }
};

// CVSS Score Graph Data
export const getCVSSScore = async () => {
  try {
    // http://localhost:3001/api/cve/cvss/stats
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/cvss/stats`
    );
    console.log(response.data);
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

// Product Data
export const getProductData = async (product) => {
  try {
    // http://localhost:3001/api/cve/product/:product/versions
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/product/${product}/versions`
    );
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

// getProductVulnerabilityData
export const getProductVulnerabilityData = async (
  product,
  version,
  year,
  month,
  sortBy
) => {
  try {
    // http://localhost:3001/api/cve/product/Android/version/13/filtered?year=2024&month=09&sortBy=publishDate:desc
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/product/${product}/version/${version}/filtered?year=${year}&month=${month}&sortBy=${sortBy}`
    );
    console.log(response.data);
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

export const getFeed = async (
  limit,
  page,
  watchlistName = null,
  filters = []
) => {
  const token = localStorage.getItem("accessToken");
  if (!token) throw new Error("Authentication token not found");

  try {
    // Build query params
    const params = new URLSearchParams({
      page,
      limit,
    });

    if (watchlistName) {
      params.append("watchlist", watchlistName);
    }

    if (filters.length > 0) {
      params.append("filters", JSON.stringify(filters));
    }

    const response = await axios.get(
      `${process.env.SERVER_URL}/api/feed?${params.toString()}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        timeout: 10000, // 10s timeout
      }
    );

    if (!response.data || !response.data.success) {
      throw new Error("Invalid response received");
    }

    return response.data;
  } catch (err) {
    console.error("Feed fetch error:", err);
    throw err;
  }
};

export const getVendorDataByDate = async (
  vendor,
  year,
  month,
  sortBy,
  order,
  page,
  limit
) => {
  try {
    // http://localhost:3001/api/cve/product/Android/version/13/filtered?year=2024&month=09&sortBy=publishDate:desc
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/vendor/${vendor}/year/${year}/filtered?month=${month}&sortBy=${sortBy}:${order}&page=${page}&limit=${limit}`
    );
    console.log(response.data);
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

export const getProductDataByDate = async (
  product,
  version,
  year,
  month,
  sortBy,
  order,
  page,
  limit
) => {
  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/product/${product}/version/${version}/filtered?year=${year}&month=${month}&sortBy=${sortBy}:${order}&page=${page}&limit=${limit}`
    );
    console.log(response.data);
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

// getVendorsList
export const getVendorsList = async (page, limit) => {
  try {
    // http://localhost:3001/api/cve/product/:product/version/:version/vulnerabilities
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/vendors/alphabetical?page=${page}&limit=${limit}`
    );
    console.log(response.data);
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

// getProductsList
export const getProductsList = async (page, limit) => {
  try {
    // http://localhost:3000/api/cve/products/alphabetical?page=1&limit=200
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/products/alphabetical?page=${page}&limit=${limit}`
    );
    console.log(response.data);
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

//Vendors Filtering Function
export const getVendorsByAlphabet = async (alphabet, page, limit) => {
  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/vendors/alphabetical/${alphabet}?page=${page}&limit=${limit}`
    );
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

//Products Filtering Function
export const getProductsByAlphabet = async (alphabet, page, limit) => {
  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/cve/products/alphabetical/${alphabet}?page=${page}&limit=${limit}`
    );
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

//Recent CVE's updates
export const getRecentCVEsUpdate = async (period) => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    setError("No authentication token found");
    return;
  }

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/dashboard/recent-cves/${period}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    if (response.status !== 200) {
      throw new Error(`Something went wrong, STATUS: ${response.status}`);
    }
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

//Unpatched Fixable CVEs
export const getUnpatchedFixableCVEs = async () => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    setError("No authentication token found");
    return;
  }

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/dashboard/unpatched-fixable-cves`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    if (response.status !== 200) {
      throw new Error(`Something went wrong, STATUS: ${response.status}`);
    }
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

//Live Exploits Alert
export const getLiveExploits = async () => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    setError("No authentication token found");
    return;
  }

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/dashboard/live-exploits`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    if (response.status !== 200) {
      throw new Error(`Something went wrong, STATUS: ${response.status}`);
    }
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

// Add this optimized function to your fetch.js file
export const getResolutionsCVEs = async (page = 1, limit = 10) => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    throw new Error("No authentication token found");
  }

  // Add a timestamp to prevent browser caching
  const timestamp = new Date().getTime();

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/resolutions?page=${page}&limit=${limit}&_t=${timestamp}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        // Add a timeout to abort requests that take too long
        timeout: 10000,
      }
    );
    return response.data;
  } catch (err) {
    console.error("Error fetching resolutions:", err);
    throw new Error("Failed to fetch resolutions data");
  }
};

// Add this optimized function to your fetch.js file
export const getTopCompanies = async () => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    throw new Error("No authentication token found");
  }

  // Add a timestamp to prevent browser caching
  const timestamp = new Date().getTime();

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/dashboard/watchlist-vendor-stats`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        // Add a timeout to abort requests that take too long
        //timeout: 10000,
      }
    );
    return response.data;
  } catch (err) {
    console.error("Error fetching resolutions:", err);
    throw new Error("Failed to fetch resolutions data");
  }
};

// Radial Top companies Graph data
export const getTopCompaniesRadial = async () => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    throw new Error("No authentication token found");
  }

  // Add a timestamp to prevent browser caching
  const timestamp = new Date().getTime();

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/dashboard/watchlist-vendor-stats-radial`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        // Add a timeout to abort requests that take too long
        timeout: 10000,
      }
    );
    return response.data;
  } catch (err) {
    console.error("Error fetching Top Companies Radial Chart DATA:", err);
    throw new Error("Failed to fetch Top Companies Radial Chart DATA");
  }
};
  
//Unpatched Fixable CVEs
export const getRiskLevelOverview = async () => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    setError("No authentication token found");
    return;
  }

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/dashboard/fixable-cve-stats`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    if (response.status !== 200) {
      throw new Error(`Something went wrong, STATUS: ${response.status}`);
    }
    return response.data;
  } catch (err) {
    console.error(err);
  }
};

//Unpatched Fixable CVEs
export const updateProductVersion = 
  async (type, value, watchlistName, version) => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
      toast.error("Token Expired");
        return false;
  }

  try {
        const response = await axios.post(
          `${process.env.SERVER_URL}/api/watchlist/update/item`,
          { 
              [type]: value,
              watchlist: watchlistName,
              version,
          },
          { 
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          });

    if (response.status !== 200) {
      throw new Error(`Something went wrong, STATUS: ${response.status}`);
    }
    toast.success(`${value} upgraded to ${version}`);
    return true;
  } catch (err) {
    console.error(err);
  }
};


export const getTotalFixableCves = async () => {
  const token = localStorage.getItem("accessToken");
  if (!token) {
    throw new Error("No authentication token found");
  }

  try {
    const response = await axios.get(
      `${process.env.SERVER_URL}/api/fixable-cves`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    if (response.status !== 200) {
      throw new Error(`Something went wrong, STATUS: ${response.status}`);
    }
    return response.data;
  } catch (err) {
    console.error("Error fetching total fixable CVEs:", err);
    throw err;
  }
};

