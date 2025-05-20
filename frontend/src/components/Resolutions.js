import { useState, useEffect, useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts";
import axios from "axios";
import { useToast } from "@/hooks/use-toast";

// Keep the height for the table
const height = "250px";

// Keep sample data for the bar chart
const barChartData = [
  // Your existing bar chart data...
  {
    name: "Day 1",
    cvesAddedToday: 120,
    cvesResolvedToday: 80,
  },
  {
    name: "Day 2",
    cvesAddedToday: 90,
    cvesResolvedToday: 60,
  },
  {
    name: "Day 3",
    cvesAddedToday: 110,
    cvesResolvedToday: 70,
  },
  {
    name: "Day 4",
    cvesAddedToday: 130,
    cvesResolvedToday: 90,
  },
  {
    name: "Day 5",
    cvesAddedToday: 100,
    cvesResolvedToday: 65,
  },
  {
    name: "Day 6",
    cvesAddedToday: 140,
    cvesResolvedToday: 95,
  },
  {
    name: "Day 7",
    cvesAddedToday: 105,
    cvesResolvedToday: 75,
  },
  {
    name: "Day 8",
    cvesAddedToday: 125,
    cvesResolvedToday: 85,
  },
  {
    name: "Day 9",
    cvesAddedToday: 115,
    cvesResolvedToday: 80,
  },
  {
    name: "Day 10",
    cvesAddedToday: 135,
    cvesResolvedToday: 90,
  },
  {
    name: "Day 11",
    cvesAddedToday: 95,
    cvesResolvedToday: 65,
  },
  {
    name: "Day 12",
    cvesAddedToday: 120,
    cvesResolvedToday: 80,
  },
  {
    name: "Day 13",
    cvesAddedToday: 110,
    cvesResolvedToday: 75,
  },
  {
    name: "Day 14",
    cvesAddedToday: 130,
    cvesResolvedToday: 90,
  },
  {
    name: "Day 15",
    cvesAddedToday: 100,
    cvesResolvedToday: 70,
  },
  {
    name: "Day 16",
    cvesAddedToday: 140,
    cvesResolvedToday: 95,
  },
  {
    name: "Day 17",
    cvesAddedToday: 105,
    cvesResolvedToday: 75,
  },
  {
    name: "Day 18",
    cvesAddedToday: 125,
    cvesResolvedToday: 85,
  },
  {
    name: "Day 19",
    cvesAddedToday: 115,
    cvesResolvedToday: 80,
  },
  {
    name: "Day 20",
    cvesAddedToday: 135,
    cvesResolvedToday: 90,
  },
  {
    name: "Day 21",
    cvesAddedToday: 95,
    cvesResolvedToday: 65,
  },
  {
    name: "Day 22",
    cvesAddedToday: 120,
    cvesResolvedToday: 80,
  },
  {
    name: "Day 23",
    cvesAddedToday: 110,
    cvesResolvedToday: 75,
  },
  {
    name: "Day 24",
    cvesAddedToday: 130,
    cvesResolvedToday: 90,
  },
  {
    name: "Day 25",
    cvesAddedToday: 100,
    cvesResolvedToday: 70,
  },
  {
    name: "Day 26",
    cvesAddedToday: 140,
    cvesResolvedToday: 95,
  },
  {
    name: "Day 27",
    cvesAddedToday: 105,
    cvesResolvedToday: 75,
  },
  {
    name: "Day 28",
    cvesAddedToday: 125,
    cvesResolvedToday: 85,
  },
  {
    name: "Day 29",
    cvesAddedToday: 115,
    cvesResolvedToday: 80,
  },
  {
    name: "Day 30",
    cvesAddedToday: 135,
    cvesResolvedToday: 90,
  },
  {
    name: "Day 31",
    cvesAddedToday: 95,
    cvesResolvedToday: 65,
  },
];

// Sample data for critical news
const criticalNews = [
  // Your existing critical news data...
  {
    title: "Critical Vulnerability Discovered in Popular Library",
    date: "2023-02-18",
  },
  { title: "New Exploit Targets Unpatched Systems", date: "2023-02-22" },
  {
    title: "Zero-Day Exploit Released for Popular Software",
    date: "2023-02-29",
  },
  { title: "Major Security Breach in Financial Sector", date: "2023-01-25" },
  {
    title: "Patch Released for Critical Software Vulnerability",
    date: "2023-01-30",
  },
  { title: "Unpatched Systems Vulnerable to New Exploit", date: "2023-02-05" },
  { title: "Ransomware Attack Hits Government Agencies", date: "2023-02-10" },
  { title: "Security Flaw Exposed in Popular CMS", date: "2023-02-15" },
  {
    title: "Critical Vulnerability Found in Database Software",
    date: "2023-02-18",
  },
  {
    title: "New Malware Spreading Through Social Media Platforms",
    date: "2023-02-22",
  },
  { title: "Zero-Day Exploit Discovered in Mobile OS", date: "2023-02-25" },
  { title: "Major Cyberattack Targets Energy Sector", date: "2023-03-01" },
];

// Sample data for recent updates
const recentUpdates = [
  // Your existing recent updates data...
  { title: "Update 1.2.3 Released with Security Fixes", date: "2023-02-25" },
  { title: "New Feature Added to Popular Software", date: "2023-02-22" },
  {
    title: "Security Patch Released for Critical Vulnerability",
    date: "2023-02-18",
  },
  { title: "Critical Bug Fix Released for Popular App", date: "2023-02-22" },
  {
    title: "New Analytics Feature Added to Productivity Tool",
    date: "2023-02-20",
  },
  {
    title: "Version 5.0 Launches with Advanced Security Features",
    date: "2023-02-18",
  },
  { title: "Update 4.2.0 Focuses on System Stability", date: "2023-02-15" },
  {
    title: "Performance Improvements Included in Latest Patch",
    date: "2023-02-12",
  },
  { title: "New Collaboration Tool Added to Suite", date: "2023-02-10" },
  { title: "Update 1.9.9 Released with Minor Fixes", date: "2023-02-05" },
  {
    title: "Critical Security Update Available for Download",
    date: "2023-01-30",
  },
];

function Resolutions() {
  // State variables
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [pageOpen, setPageOpen] = useState(1);
  const [pageResolved, setPageResolved] = useState(1);
  const [pageManhandled, setPageManhandled] = useState(1);
  const [pageIgnored, setPageIgnored] = useState(1);
  const [totalPagesOpen, setTotalPagesOpen] = useState(1);
  const [totalPagesResolved, setTotalPagesResolved] = useState(1);
  const [totalPagesManhandled, setTotalPagesManhandled] = useState(1);
  const [totalPagesIgnored, setTotalPagesIgnored] = useState(1);
  const [limit, setLimit] = useState(10);
  const [showBarChart, setShowBarChart] = useState(true);
  const [showCriticalNewsPopup, setShowCriticalNewsPopup] = useState(false);
  const [showRecentUpdatesPopup, setShowRecentUpdatesPopup] = useState(false);
  const [criticalNewsSort, setCriticalNewsSort] = useState("date-asc");
  const [recentUpdatesSort, setRecentUpdatesSort] = useState("date-asc");
  const { toast } = useToast();

  // Keep your existing UI state
  const [products, setProducts] = useState([
    {
      name: "Chrome",
      versions: [
        "131.0.0.0",
        "130.0.0.0",
        "129.0.0.0",
        "128.0.0.0",
        "127.0.0.0",
      ],
      selectedVersion: "131.0.0.0",
    },
    {
      name: "Firefox",
      versions: ["118.0", "117.0", "116.0", "115.0", "114.0"],
      selectedVersion: "118.0",
    },
    {
      name: "Safari",
      versions: ["17.0", "16.5", "16.4", "16.3", "16.2"],
      selectedVersion: "17.0",
    },
    {
      name: "Edge",
      versions: ["117.0.2045.60", "116.0.1938.62"],
      selectedVersion: "117.0.2045.60",
    },
  ]);
  const [selectedProducts, setSelectedProducts] = useState([]);
  const [showAddProductModal, setShowAddProductModal] = useState(false);
  const [isOpen, setIsOpen] = useState({});
  const [tableDataOpen, setTableDataOpen] = useState([]);
  const [tableDataResolved, setTableDataResolved] = useState([]);
  const [tableDataManhandled, setTableDataManhandled] = useState([]);
  const [tableDataIgnored, setTableDataIgnored] = useState([]);
  const [showTab, setShowTab] = useState("open");
  const [selectedCves, setSelectedCves] = useState({});
  const [showMoveOptions, setShowMoveOptions] = useState(false);
  const [newProductName, setNewProductName] = useState("");
  const [newProductOptions, setNewProductOptions] = useState("");

  // Optimized fetchData function
  const fetchData = useCallback(async () => {
    if (!localStorage.getItem("accessToken")) {
      setError("Authentication required");
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      const timestamp = new Date().getTime(); // Prevent browser caching

      // Get all CVEs from resolutions endpoint
      const [resolutionsResponse, statusesResponse] = await Promise.all([
        axios.get(
          `${process.env.SERVER_URL}/api/resolutions?page=1&limit=1000&_t=${timestamp}`,
          {
            headers: {
              Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
              "Content-Type": "application/json",
            },
            timeout: 10000, // 10s timeout
          }
        ),
        // Also fetch user's CVE status settings
        axios.get(`${process.env.SERVER_URL}/api/resolution/status`, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            "Content-Type": "application/json",
          },
          timeout: 10000,
        }),
      ]);

      if (resolutionsResponse.data && resolutionsResponse.data.success) {
        setData(resolutionsResponse.data.data);
        setError(null);

        // Create a map of CVE statuses for quick lookup
        const cveStatusMap = {};
        if (statusesResponse.data && statusesResponse.data.success) {
          statusesResponse.data.data.forEach((item) => {
            cveStatusMap[item.cve_id] = item.status;
          });
        }

        // Update table data based on fetched CVEs
        const fetchedCves = resolutionsResponse.data.data || [];

        // Format the CVE data for table display with statuses from user settings
        const formattedCves = fetchedCves.map((cve) => ({
          cveNo: cve.cve_id,
          details: cve.description,
          // Use the status from user settings if available, otherwise default to open
          status: cveStatusMap[cve.cve_id] || "open",
          cvss: cve.cvss_score,
          epss: cve.epss_score,
          published: cve.published_at,
          updated: cve.updated_at,
        }));

        // Filter CVEs into their respective status tables
        const openCves = formattedCves.filter((cve) => cve.status === "open");
        const resolvedCves = formattedCves.filter(
          (cve) => cve.status === "resolved"
        );
        const manhandledCves = formattedCves.filter(
          (cve) => cve.status === "manhandled"
        );
        const ignoredCves = formattedCves.filter(
          (cve) => cve.status === "ignored"
        );

        // Set the filtered data to state
        setTableDataOpen(openCves);
        setTableDataResolved(resolvedCves);
        setTableDataManhandled(manhandledCves);
        setTableDataIgnored(ignoredCves);

        // Calculate total pages for each tab
        setTotalPagesOpen(Math.ceil(openCves.length / limit));
        setTotalPagesResolved(Math.ceil(resolvedCves.length / limit));
        setTotalPagesManhandled(Math.ceil(manhandledCves.length / limit));
        setTotalPagesIgnored(Math.ceil(ignoredCves.length / limit));
      } else {
        setError("Invalid response structure");
      }
    } catch (err) {
      console.error("Error fetching resolutions:", err);
      setError(err.message || "Failed to load data");
    } finally {
      setLoading(false);
    }
  }, [limit]);

  // Fetch data when component mounts or dependencies change
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Function to get current page based on active tab
  const getCurrentPage = () => {
    switch (showTab) {
      case "open":
        return pageOpen;
      case "resolved":
        return pageResolved;
      case "manhandled":
        return pageManhandled;
      case "ignored":
        return pageIgnored;
      default:
        return 1;
    }
  };

  // Function to get total pages based on active tab
  const getCurrentTotalPages = () => {
    switch (showTab) {
      case "open":
        return totalPagesOpen;
      case "resolved":
        return totalPagesResolved;
      case "manhandled":
        return totalPagesManhandled;
      case "ignored":
        return totalPagesIgnored;
      default:
        return 1;
    }
  };

  // Function to set current page based on active tab
  const setCurrentPage = (page) => {
    switch (showTab) {
      case "open":
        setPageOpen(page);
        break;
      case "resolved":
        setPageResolved(page);
        break;
      case "manhandled":
        setPageManhandled(page);
        break;
      case "ignored":
        setPageIgnored(page);
        break;
    }
  };

  // Handle pagination
  const handleNextPage = () => {
    const currentPage = getCurrentPage();
    const totalPages = getCurrentTotalPages();

    if (currentPage < totalPages) {
      setCurrentPage(currentPage + 1);
    }
  };

  const handlePrevPage = () => {
    const currentPage = getCurrentPage();

    if (currentPage > 1) {
      setCurrentPage(currentPage - 1);
    }
  };

  // Event handlers
  const handleTabChange = (tab) => {
    setShowTab(tab);

    // Refresh data when switching tabs to ensure we have the latest status information
    fetchData();
  };

  const handleCveSelection = (cveId) => {
    setSelectedCves((prevSelectedCves) => {
      return { ...prevSelectedCves, [cveId]: !prevSelectedCves[cveId] };
    });
  };

  const handleProductSelection = (productName) => {
    if (selectedProducts.includes(productName)) {
      setSelectedProducts(
        selectedProducts.filter((product) => product !== productName)
      );
    } else {
      setSelectedProducts([...selectedProducts, productName]);
    }
  };

  const handleOptionChange = (productName, selectedVersion) => {
    setProducts(
      products.map((product) => {
        if (product.name === productName) {
          return { ...product, selectedVersion };
        }
        return product;
      })
    );
  };

  const handleAddProduct = (e) => {
    e.preventDefault();
    const newProduct = {
      name: newProductName,
      versions: newProductOptions.split(",").map((option) => option.trim()),
      selectedVersion: newProductOptions
        .split(",")
        .map((option) => option.trim())[0],
    };
    setProducts([...products, newProduct]);
    setNewProductName("");
    setNewProductOptions("");
    setShowAddProductModal(false);
  };

  const handleMoveTo = (status) => {
    // Get CVE IDs of selected CVEs
    const selectedCveIds = Object.keys(selectedCves).filter(
      (id) => selectedCves[id]
    );

    if (selectedCveIds.length === 0) {
      return;
    }

    // Update status in backend
    updateCveStatus(selectedCveIds, status);

    // Clear selections
    setShowMoveOptions(false);
    setSelectedCves({});
  };

  // Function to update CVE status
  const updateCveStatus = async (cveIds, status) => {
    const token = localStorage.getItem("accessToken");
    if (!token) {
      setError("Authentication required");
      return;
    }

    try {
      const response = await axios.post(
        `${process.env.SERVER_URL}/api/resolution/status`,
        {
          cve_ids: cveIds,
          status,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (response.data && response.data.success) {
        // Success notification
        toast({
          title: "Status Updated",
          description: `${cveIds.length} CVE${
            cveIds.length > 1 ? "s" : ""
          } moved to ${status}.`,
        });

        // Always fetch fresh data after status updates
        fetchData();
      } else {
        throw new Error("Status update failed");
      }
    } catch (err) {
      console.error("Error updating CVE status:", err);
      setError(err.message || "Failed to update CVE status");

      // Refresh data to ensure UI is consistent with backend state
      fetchData();
    }
  };

  // Monitor selected CVEs to show/hide move options
  useEffect(() => {
    const hasSelectedCves = Object.values(selectedCves).some((value) => value);
    setShowMoveOptions(hasSelectedCves);
  }, [selectedCves]);

  // Sort functions
  const getSortedCriticalNews = () => {
    return [...criticalNews].sort((a, b) => {
      if (criticalNewsSort === "date-asc") {
        return new Date(a.date) - new Date(b.date);
      } else if (criticalNewsSort === "date-desc") {
        return new Date(b.date) - new Date(a.date);
      } else if (criticalNewsSort === "title-asc") {
        return a.title.localeCompare(b.title);
      } else if (criticalNewsSort === "title-desc") {
        return b.title.localeCompare(a.title);
      }
      return 0;
    });
  };

  const getSortedRecentUpdates = () => {
    return [...recentUpdates].sort((a, b) => {
      if (recentUpdatesSort === "date-asc") {
        return new Date(a.date) - new Date(b.date);
      } else if (recentUpdatesSort === "date-desc") {
        return new Date(b.date) - new Date(a.date);
      } else if (recentUpdatesSort === "title-asc") {
        return a.title.localeCompare(b.title);
      } else if (recentUpdatesSort === "title-desc") {
        return b.title.localeCompare(a.title);
      }
      return 0;
    });
  };

  // Get current tab data
  const getCurrentTabData = () => {
    const currentPage = getCurrentPage();
    const startIndex = (currentPage - 1) * limit;
    const endIndex = startIndex + limit;

    switch (showTab) {
      case "open":
        return tableDataOpen.slice(startIndex, endIndex);
      case "resolved":
        return tableDataResolved.slice(startIndex, endIndex);
      case "manhandled":
        return tableDataManhandled.slice(startIndex, endIndex);
      case "ignored":
        return tableDataIgnored.slice(startIndex, endIndex);
      default:
        return [];
    }
  };

  return (
    <div className="flex-1 flex bg-[#0B0E1E] text-gray-300">
      {/* Left-Hand Side Menu */}
      <div className="w-64 bg-[#1E233B] p-4">
        <div className="flex justify-between mb-4">
          <h2 className="text-lg font-bold text-[#00D1FF]">Products</h2>
          <button
            className="bg-[#00D1FF] text-white py-2 px-4 rounded"
            onClick={() => setShowAddProductModal(true)}
          >
            Add Product
          </button>
        </div>
        <ul>
          {products.map((product, index) => (
            <li
              key={index}
              className="flex items-center p-2 cursor-pointer hover:bg-[#282F47] rounded"
            >
              <input
                type="checkbox"
                checked={selectedProducts.includes(product.name)}
                onChange={() => handleProductSelection(product.name)}
                className="mr-2"
              />
              <span className="mr-2">{product.name}</span>
              <select
                value={product.selectedVersion}
                onChange={(e) =>
                  handleOptionChange(product.name, e.target.value)
                }
                className="bg-[#1E233B] text-[#00D1FF] border border-[#00D1FF] py-1 px-2 rounded"
              >
                {product.versions.map((version, index) => (
                  <option key={index} value={version}>
                    {version}
                  </option>
                ))}
              </select>
            </li>
          ))}
        </ul>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 p-6 flex flex-col">
        <button
          className={
            "bg-[#282F47] hover:bg-[#2C3454] text-[#00D1FF] py-2 px-4 rounded-md transition duration-150"
          }
          onClick={() => setShowBarChart(!showBarChart)}
        >
          {showBarChart ? "Hide Chart" : "Show Chart"}
        </button>
        {/* Stacked Bar Chart */}
        {showBarChart && (
          <div className="mb-8">
            <h2 className="text-2xl font-bold mb-4 text-[#00D1FF]">
              Resolution Statistics
            </h2>
            <BarChart width={800} height={200} data={barChartData}>
              <XAxis
                dataKey="name"
                stroke="#00D1FF"
                tick={{ fontSize: 12 }}
                interval={5} // Show every 5th tick
              />
              <YAxis stroke="#00D1FF" />
              <Tooltip />
              <Legend />
              <Bar
                dataKey="cvesAddedToday"
                fill="#009DBD"
                radius={[0, 0, 0, 0]}
                barSize={20}
                stackId="a"
                isAnimationActive={true}
              />
              <Bar
                dataKey="cvesResolvedToday"
                fill="#FF69B4"
                radius={[5, 5, 0, 0]}
                barSize={20}
                stackId="a"
                isAnimationActive={true}
              />
            </BarChart>
          </div>
        )}

        {/* Middle Content Area */}
        <div className="flex justify-between mb-4">
          {/* Tabs */}
          <div className="flex flex-col">
            <h2 className="text-2xl font-bold mb-4 text-[#00D1FF]">
              Resolution Details
            </h2>
            <div className="flex">
              {["open", "resolved", "manhandled", "ignored"].map((tab) => (
                <button
                  key={tab}
                  className={`bg-[#282F47] hover:bg-[#2C3454] text-[#00D1FF] py-2 px-4 rounded-t-md transition duration-150 
                    ${showTab === tab ? "bg-[#2C3454]" : ""}`}
                  onClick={() => handleTabChange(tab)}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Pagination controls */}
          <div className="flex items-center space-x-2">
            <button
              onClick={handlePrevPage}
              disabled={getCurrentPage() <= 1}
              className="px-2 py-1 rounded bg-[#282F47] disabled:opacity-50"
            >
              Prev
            </button>
            <span>
              Page {getCurrentPage()} of {getCurrentTotalPages()}
            </span>
            <button
              onClick={handleNextPage}
              disabled={getCurrentPage() >= getCurrentTotalPages()}
              className="px-2 py-1 rounded bg-[#282F47] disabled:opacity-50"
            >
              Next
            </button>
          </div>

          {/* Show Move Options */}
          {showMoveOptions && (
            <div className="flex">
              <button
                className="bg-slate-950/75 text-gray-300 hover:bg-slate-950/50 hover:text-gray-200 py-2 px-4 rounded-lg"
                onClick={() => handleMoveTo("open")}
              >
                Move to Open
              </button>
              <button
                className="bg-slate-950/75 text-gray-300 hover:bg-slate-950/50 hover:text-gray-200 py-2 px-4 rounded-lg"
                onClick={() => handleMoveTo("resolved")}
              >
                Move to Resolved
              </button>
              <button
                className="bg-slate-950/75 text-gray-300 hover:bg-slate-950/50 hover:text-gray-200 py-2 px-4 rounded-lg"
                onClick={() => handleMoveTo("manhandled")}
              >
                Move to Manhandled
              </button>
              <button
                className="bg-slate-950/75 text-gray-300 hover:bg-slate-950/50 hover:text-gray-200 py-2 px-4 rounded-lg"
                onClick={() => handleMoveTo("ignored")}
              >
                Move to Ignored
              </button>
            </div>
          )}
        </div>

        {/* Content based on loading state */}
        {loading ? (
          <div className="flex justify-center p-8">
            <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-500"></div>
          </div>
        ) : error ? (
          <div className="bg-red-100 text-red-700 p-4 rounded mb-4">
            {error}
          </div>
        ) : (
          <div
            className="scrollbar"
            style={{
              maxHeight: showBarChart ? height : "calc(100vh - 200px)",
              overflowY: "auto",
              overflowX: "hidden",
            }}
          >
            {getCurrentTabData().length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No {showTab} vulnerabilities found
              </div>
            ) : (
              getCurrentTabData().map((row, index) => (
                <div
                  key={index}
                  className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm p-4 mb-4 shadow-md relative"
                >
                  <div className="flex">
                    <input
                      type="checkbox"
                      className="mr-2"
                      checked={selectedCves[row.cveNo] === true}
                      onChange={() => handleCveSelection(row.cveNo)}
                      id={row.cveNo}
                    />
                    <label htmlFor={row.cveNo} className="flex-1">
                      <div>
                        <h3 className="text-lg font-bold text-[#00B7EF]">
                          {row.cveNo}
                        </h3>
                        <p className="text-sm max-w-md overflow-wrap break-words text-gray-300">
                          {row.details}
                        </p>
                      </div>
                    </label>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* Right-Hand Side Pane */}
      <div className="w-64 bg-[#1E233B] p-4">
        {/* Critical News Section */}
        <div className="mb-8">
          <div className="flex flex-col">
            <h2 className="text-lg font-bold mb-1 text-[#00D1FF]">
              Critical News
            </h2>
            <span
              className="text-xs text-gray-500 cursor-pointer hover:text-gray-300"
              onClick={() => setShowCriticalNewsPopup(true)}
            >
              View More
            </span>
          </div>
          <ul>
            {getSortedCriticalNews()
              .slice(0, 3)
              .map((news, index) => (
                <li key={index} className="p-2 hover:bg-[#282F47] rounded">
                  <span className="text-sm text-gray-300">{news.title}</span>
                  <br />
                  <span className="text-xs text-gray-500">{news.date}</span>
                </li>
              ))}
          </ul>
        </div>

        {/* Recent Updates Section */}
        <div>
          <div className="flex flex-col">
            <h2 className="text-lg font-bold mb-1 text-[#00D1FF]">
              Recent Updates
            </h2>
            <span
              className="text-xs text-gray-500 cursor-pointer hover:text-gray-300"
              onClick={() => setShowRecentUpdatesPopup(true)}
            >
              View More
            </span>
          </div>
          <ul>
            {getSortedRecentUpdates()
              .slice(0, 3)
              .map((update, index) => (
                <li key={index} className="p-2 hover:bg-[#282F47] rounded">
                  <span className="text-sm text-gray-300">{update.title}</span>
                  <br />
                  <span className="text-xs text-gray-500">{update.date}</span>
                </li>
              ))}
          </ul>
        </div>
      </div>

      {/* Critical News Popup */}
      {showCriticalNewsPopup && (
        <div
          className="fixed top-0 left-0 w-full h-full bg-[#00000080] flex justify-center items-center"
          onClick={() => setShowCriticalNewsPopup(false)}
        >
          <div
            className="bg-[#1E233B] p-4 rounded-lg shadow-md w-1/2"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 className="text-lg font-bold mb-4 text-[#00D1FF]">
              Critical News
            </h2>
            <div
              className="flex justify-between overflow-y-auto mb-4"
              style={{ maxHeight: "calc(100vh - 200px)" }}
            >
              <select
                className="bg-[#282F47] hover:bg-[#2C3454] text-[#00D1FF] py-2 px-4 rounded-md transition duration-150"
                value={criticalNewsSort}
                onChange={(e) => setCriticalNewsSort(e.target.value)}
              >
                <option value="date-asc">Sort by Date (Ascending)</option>
                <option value="date-desc">Sort by Date (Descending)</option>
                <option value="title-asc">Sort by Title (Ascending)</option>
                <option value="title-desc">Sort by Title (Descending)</option>
              </select>
            </div>
            <div
              className="scrollbar"
              style={{
                maxHeight: "calc(100vh - 250px)",
                overflowY: "auto",
                overflowX: "hidden",
              }}
            >
              <ul>
                {getSortedCriticalNews().map((news, index) => (
                  <li key={index} className="p-2 hover:bg-[#282F47] rounded">
                    <span className="text-sm text-gray-300">{news.title}</span>
                    <br />
                    <span className="text-xs text-gray-500">{news.date}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Recent Updates Popup */}
      {showRecentUpdatesPopup && (
        <div
          className="fixed top-0 left-0 w-full h-full bg-[#00000080] flex justify-center items-center"
          onClick={() => setShowRecentUpdatesPopup(false)}
        >
          <div
            className="bg-[#1E233B] p-4 rounded-lg shadow-md w-1/2"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 className="text-lg font-bold mb-4 text-[#00D1FF]">
              Recent Updates
            </h2>
            <div className="flex justify-between mb-4">
              <select
                className="bg-[#282F47] hover:bg-[#2C3454] text-[#00D1FF] py-2 px-4 rounded-md transition duration-150"
                value={recentUpdatesSort}
                onChange={(e) => setRecentUpdatesSort(e.target.value)}
              >
                <option value="date-asc">Sort by Date (Ascending)</option>
                <option value="date-desc">Sort by Date (Descending)</option>
                <option value="title-asc">Sort by Title (Ascending)</option>
                <option value="title-desc">Sort by Title (Descending)</option>
              </select>
            </div>
            <div
              className="scrollbar"
              style={{
                maxHeight: "calc(100vh - 250px)",
                overflowY: "auto",
                overflowX: "hidden",
              }}
            >
              <ul>
                {getSortedRecentUpdates().map((update, index) => (
                  <li key={index} className="p-2 hover:bg-[#282F47] rounded">
                    <span className="text-sm text-gray-300">
                      {update.title}
                    </span>
                    <br />
                    <span className="text-xs text-gray-500">{update.date}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Add Product Modal */}
      {showAddProductModal && (
        <div className="fixed top-0 left-0 w-full h-screen bg-[#1E233B] bg-opacity-50 flex justify-center items-center">
          <div className="bg-[#1E233B] p-4 rounded">
            <h2 className="text-lg font-bold text-[#00D1FF] mb-4">
              Add Product
            </h2>
            <form onSubmit={handleAddProduct}>
              <input
                type="text"
                value={newProductName}
                onChange={(e) => setNewProductName(e.target.value)}
                className="bg-[#1E233B] text-[#00D1FF] border border-[#00D1FF] py-1 px-2 rounded mb-4"
                placeholder="Product Name"
              />
              <input
                type="text"
                value={newProductOptions}
                onChange={(e) => setNewProductOptions(e.target.value)}
                className="bg-[#1E233B] text-[#00D1FF] border border-[#00D1FF] py-1 px-2 rounded mb-4"
                placeholder="Product Versions (comma separated)"
              />
              <div className="flex justify-between">
                <button
                  type="button"
                  onClick={() => setShowAddProductModal(false)}
                  className="bg-slate-700 text-white py-2 px-4 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-[#00D1FF] text-white py-2 px-4 rounded"
                >
                  Add Product
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default Resolutions;
