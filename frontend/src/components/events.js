import { useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts"; // For bar chart

var height = '250px';//table height

// Sample data for the bar chart
const barChartData = [
  { "name": "1st Jan", "exploitsPerDay": 5 },
  { "name": "2nd Jan", "exploitsPerDay": 12 },
  { "name": "3rd Jan", "exploitsPerDay": 8 },
  { "name": "4th Jan", "exploitsPerDay": 15 },
  { "name": "5th Jan", "exploitsPerDay": 10 },
  { "name": "6th Jan", "exploitsPerDay": 18 },
  { "name": "7th Jan", "exploitsPerDay": 7 },
  { "name": "8th Jan", "exploitsPerDay": 13 },
  { "name": "9th Jan", "exploitsPerDay": 20 },
  { "name": "10th Jan", "exploitsPerDay": 14 },
  { "name": "11th Jan", "exploitsPerDay": 22 },
  { "name": "12th Jan", "exploitsPerDay": 16 },
  { "name": "13th Jan", "exploitsPerDay": 25 },
  { "name": "14th Jan", "exploitsPerDay": 19 },
  { "name": "15th Jan", "exploitsPerDay": 11 },
  { "name": "16th Jan", "exploitsPerDay": 23 },
  { "name": "17th Jan", "exploitsPerDay": 17 },
  { "name": "18th Jan", "exploitsPerDay": 26 },
  { "name": "19th Jan", "exploitsPerDay": 14 },
  { "name": "20th Jan", "exploitsPerDay": 21 },
  { "name": "21st Jan", "exploitsPerDay": 18 },
  { "name": "22nd Jan", "exploitsPerDay": 24 },
  { "name": "23rd Jan", "exploitsPerDay": 15 },
  { "name": "24th Jan", "exploitsPerDay": 22 },
  { "name": "25th Jan", "exploitsPerDay": 20 },
  { "name": "26th Jan", "exploitsPerDay": 27 },
  { "name": "27th Jan", "exploitsPerDay": 19 },
  { "name": "28th Jan", "exploitsPerDay": 23 },
  { "name": "29th Jan", "exploitsPerDay": 16 },
  { "name": "30th Jan", "exploitsPerDay": 25 },
  { "name": "31st Jan", "exploitsPerDay": 20 }
];

// Sample data for the table
const tableData = [
  {
    cveNo: "CVE-2022-1234",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-5678",
    products: "MacOS, iOS",
    details: "Details about the exploit",
    exploitability: "Medium",
  },
  {
    cveNo: "CVE-2022-9012",
    products: "Android, ChromeOS",
    details: "Details about the exploit",
    exploitability: "Low",
  },
  {
    cveNo: "CVE-2022-1111",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-1234",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-5678",
    products: "MacOS, iOS",
    details: "Details about the exploit",
    exploitability: "Medium",
  },
  {
    cveNo: "CVE-2022-9012",
    products: "Android, ChromeOS",
    details: "Details about the exploit",
    exploitability: "Low",
  },
  {
    cveNo: "CVE-2022-1111",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-1234",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-5678",
    products: "MacOS, iOS",
    details: "Details about the exploit",
    exploitability: "Medium",
  },
  {
    cveNo: "CVE-2022-9012",
    products: "Android, ChromeOS",
    details: "Details about the exploit",
    exploitability: "Low",
  },
  {
    cveNo: "CVE-2022-1111",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-1234",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-5678",
    products: "MacOS, iOS",
    details: "Details about the exploit",
    exploitability: "Medium",
  },
  {
    cveNo: "CVE-2022-9012",
    products: "Android, ChromeOS",
    details: "Details about the exploit",
    exploitability: "Low",
  },
  {
    cveNo: "CVE-2022-1111",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-1234",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-5678",
    products: "MacOS, iOS",
    details: "Details about the exploit",
    exploitability: "Medium",
  },
  {
    cveNo: "CVE-2022-9012",
    products: "Android, ChromeOS",
    details: "Details about the exploit",
    exploitability: "Low",
  },
  {
    cveNo: "CVE-2022-1111",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-1234",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
  {
    cveNo: "CVE-2022-5678",
    products: "MacOS, iOS",
    details: "Details about the exploit",
    exploitability: "Medium",
  },
  {
    cveNo: "CVE-2022-9012",
    products: "Android, ChromeOS",
    details: "Details about the exploit",
    exploitability: "Low",
  },
  {
    cveNo: "CVE-2022-1111",
    products: "Windows, Linux",
    details: "Details about the exploit",
    exploitability: "High",
  },
];

// Sample data for critical news
const criticalNews = [
  { title: "Critical Vulnerability Discovered in Popular Library", date: "2023-02-18" },
  { title: "New Exploit Targets Unpatched Systems", date: "2023-02-22" },
  { title: "Zero-Day Exploit Released for Popular Software", date: "2023-02-29" },
  { title: "Major Security Breach in Financial Sector", date: "2023-01-25" },
  { title: "Patch Released for Critical Software Vulnerability", date: "2023-01-30" },
  { title: "Unpatched Systems Vulnerable to New Exploit", date: "2023-02-05" },
  { title: "Ransomware Attack Hits Government Agencies", date: "2023-02-10" },
  { title: "Security Flaw Exposed in Popular CMS", date: "2023-02-15" },
  { title: "Critical Vulnerability Found in Database Software", date: "2023-02-18" },
  { title: "New Malware Spreading Through Social Media Platforms", date: "2023-02-22" },
  { title: "Zero-Day Exploit Discovered in Mobile OS", date: "2023-02-25" },
  { title: "Major Cyberattack Targets Energy Sector", date: "2023-03-01" }
];

// Sample data for recent updates
const recentUpdates = [
  { title: "Update 1.2.3 Released with Security Fixes", date: "2023-02-25" },
  { title: "New Feature Added to Popular Software", date: "2023-02-22" },
  { title: "Security Patch Released for Critical Vulnerability", date: "2023-02-18" },
  { title: "Critical Bug Fix Released for Popular App", date: "2023-02-22" },
  { title: "New Analytics Feature Added to Productivity Tool", date: "2023-02-20" },
  { title: "Version 5.0 Launches with Advanced Security Features", date: "2023-02-18" },
  { title: "Update 4.2.0 Focuses on System Stability", date: "2023-02-15" },
  { title: "Performance Improvements Included in Latest Patch", date: "2023-02-12" },
  { title: "New Collaboration Tool Added to Suite", date: "2023-02-10" },
  { title: "Update 1.9.9 Released with Minor Fixes", date: "2023-02-05" },
  { title: "Critical Security Update Available for Download", date: "2023-01-30" } 
];

function EventsPage() {
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [showBarChart, setShowBarChart] = useState(true);
  const [showCriticalNewsPopup, setShowCriticalNewsPopup] = useState(false);
  const [showRecentUpdatesPopup, setShowRecentUpdatesPopup] = useState(false);
  const [criticalNewsSort, setCriticalNewsSort] = useState('date-asc');
  const [recentUpdatesSort, setRecentUpdatesSort] = useState('date-asc');

  const sortedCriticalNews = criticalNews.sort((a, b) => {
    if (criticalNewsSort === 'date-asc') {
      return new Date(a.date) - new Date(b.date);
    } else if (criticalNewsSort === 'date-desc') {
      return new Date(b.date) - new Date(a.date);
    } else if (criticalNewsSort === 'title-asc') {
      return a.title.localeCompare(b.title);
    } else if (criticalNewsSort === 'title-desc') {
      return b.title.localeCompare(a.title);
    }
  });

  const sortedRecentUpdates = recentUpdates.sort((a, b) => {
    if (recentUpdatesSort === 'date-asc') {
      return new Date(a.date) - new Date(b.date);
    } else if (recentUpdatesSort === 'date-desc') {
      return new Date(b.date) - new Date(a.date);
    } else if (recentUpdatesSort === 'title-asc') {
      return a.title.localeCompare(b.title);
    } else if (recentUpdatesSort === 'title-desc') {
      return b.title.localeCompare(a.title);
    }
  });
  
// Sample data for Product Versions
const [products, setProducts] = useState([
  { name: "Chrome", versions: ["131.0.0.0", "130.0.0.0", "129.0.0.0", "128.0.0.0", "127.0.0.0", "126.0.0.0", "125.0.0.0", "124.0.0.0", "123.0.0.0", "122.0.0.0", "121.0.0.0"], selectedVersion: "131.0.0.0" },
  { name: "Firefox", versions: ["118.0", "117.0", "116.0", "115.0", "114.0", "113.0", "112.0", "111.0", "110.0", "109.0", "108.0", "107.0", "106.0"], selectedVersion: "118.0" },
  { name: "Safari", versions: ["17.0", "16.5", "16.4", "16.3", "16.2", "16.1", "16.0", "15.6", "15.5", "15.4", "15.3", "15.2"], selectedVersion: "17.0" },
  { name: "Edge", versions: ["117.0.2045.60", "116.0.1938.62", "115.0.1901.203", "114.0.1823.82", "113.0.1774.57", "112.0.1722.64", "111.0.1661.62", "110.0.1587.56"], selectedVersion: "117.0.2045.60" }
]);

  const [selectedProducts, setSelectedProducts] = useState([]);
  const [showAddProductModal, setShowAddProductModal] = useState(false);
  
  const handleProductSelection = (productName) => {
    if (selectedProducts.includes(productName)) {
      setSelectedProducts(selectedProducts.filter((product) => product !== productName));
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

  {showAddProductModal && (
    <div className="fixed top-0 left-0 w-full h-full bg-[#1E233B] bg-opacity-50 flex justify-center items-center">
      <div className="bg-[#1E233B] p-4 rounded">
        <h2 className="text-lg font-bold text-[#00D1FF] mb-4">Add Product</h2>
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
            placeholder="Product Options (comma separated)"
          />
          <button
            type="submit"
            className="bg-[#00D1FF] text-white py-2 px-4 rounded"
          >
            Add Product
          </button>
        </form>
      </div>
    </div>
  )}
  
  const [newProductName, setNewProductName] = useState("");
  const [newProductOptions, setNewProductOptions] = useState("");
  
  const handleAddProduct = (e) => {
    e.preventDefault();
    const newProduct = {
      name: newProductName,
      options: new ProductOptions.split(",").map(option => option.trim()),
    };
    setProducts([...products, newProduct]);
    setNewProductName("");
    setNewProductOptions("");
    setShowAddProductModal(false);
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
          <li key={index} className="flex items-center p-2 cursor-pointer hover:bg-[#282F47] rounded">
            <input
              type="checkbox"
              checked={selectedProducts.includes(product.name)}
              onChange={() => handleProductSelection(product.name)}
              className="mr-2"
            />
            <span className="mr-2">{product.name}</span>
            <select
              value={product.selectedVersion}
              onChange={(e) => handleOptionChange(product.name, e.target.value)}
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
        {/* Bar Chart */}
        {showBarChart && (
          <div className="mb-8">
            <h2 className="text-2xl font-bold mb-4 text-[#00D1FF]">Event Statistics</h2>
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
                dataKey="exploitsPerDay"
                fill="#009DBD"
                radius={[5, 5, 0, 0]}
                barSize={20}
                isAnimationActive={true}
              />
            </BarChart>
          </div>
        )}

        {/* Table */}
        <div className="flex-1" style={{ minWidth: '800px' }}>
          <div className="flex justify-between mb-4">
            <h2 className="text-2xl font-bold text-[#00D1FF]">Event Details</h2>
            <button
              className="bg-[#282F47] hover:bg-[#2C3454] text-[#00D1FF] py-2 px-4 rounded-md transition duration-150"
              onClick={() => setShowBarChart(!showBarChart)}
            >
              {showBarChart ? "Hide Chart" : "Show Chart"}
            </button>
          </div>
          <div className="sticky top-0 bg-[#1E233B]">
            <table className="w-full border-collapse border border-gray-700 rounded-lg shadow-md" style={{ minWidth: '800px', tableLayout: 'fixed' }}>
              <thead className="bg-linear-to-r from-[#00B3F3] via-[#009DBD] to-[#007A9E] text-white">
                <tr>
                  <th style={{ width: '20%' }} className="border border-gray-700 p-3 text-center font-semibold text-sm uppercase tracking-wider">
                    CVE No
                  </th>
                  <th style={{ width: '30%' }} className="border border-gray-700 p-3 text-center font-semibold text-sm uppercase tracking-wider">
                    Products
                  </th>
                  <th style={{ width: '30%' }} className="border border-gray-700 p-3 text-center font-semibold text-sm uppercase tracking-wider">
                    Details
                  </th>
                  <th style={{ width: '20%' }} className="border border-gray-700 p-3 text-center font-semibold text-sm uppercase tracking-wider">
                    Exploitability
                  </th>
                </tr>
              </thead>
            </table>
          </div>

          <div className="scrollbar" style={{ maxHeight: showBarChart ? height : 'calc(100vh - 200px)', overflowY: 'auto', overflowX: 'hidden' }}>
            <table className="w-full border-collapse border border-gray-700 rounded-lg shadow-md" style={{ minWidth: '800px', tableLayout: 'fixed' }}>
              <tbody>
                {tableData.map((row, index) => (
                  <tr
                    key={index}
                    className={`${
                      index % 2 === 0
                        ? "bg-[#1E233B] hover:bg-[#282F47]"
                        : "bg-[#232A4A] hover:bg-[#2C3454]"
                    } transition duration-150`}
                  >
                    <td style={{ width: '20%' }} className="border border-gray-700 p-3 text-center text-sm text-gray-300">
                      {row.cveNo}
                    </td>
                    <td style={{ width: '30%' }} className="border border-gray-700 p-3 text-center text-sm text-gray-300">
                      {row.products}
                    </td>
                    <td style={{ width: '30%' }} className="border border-gray-700 p-3 text-center text-sm text-gray-300">
                      {row.details}
                    </td>
                    <td style={{ width: '20%' }} className="border border-gray-700 p-3 text-center text-sm text-gray-300">
                      {row.exploitability}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Right-Hand Side Pane */}
      <div className="w-64 bg-[#1E233B] p-4">
      
      {/* Critical News Section */}
      <div className="mb-8">
        <div className="flex flex-col">
          <h2 className="text-lg font-bold mb-1 text-[#00D1FF]">Critical News</h2>
          <span
            className="text-xs text-gray-500 cursor-pointer hover:text-gray-300"
            onClick={() => setShowCriticalNewsPopup(true)}
          >
            View More
          </span>
        </div>
        <ul>
          {criticalNews.slice(0, 3).map((news, index) => (
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
          <h2 className="text-lg font-bold mb-1 text-[#00D1FF]">Recent Updates</h2>
          <span
            className="text-xs text-gray-500 cursor-pointer hover:text-gray-300"
            onClick={() => setShowRecentUpdatesPopup(true)}
          >
            View More
          </span>
        </div>
        <ul>
          {recentUpdates.slice(0, 3).map((update, index) => (
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
            <h2 className="text-lg font-bold mb-4 text-[#00D1FF]">Critical News</h2>
            <div className="flex justify-between overflow-y-auto mb-4" style={{ maxHeight: 'calc(100vh - 200px)' }}>
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
            <div className="scrollbar" style={{ maxHeight: 'calc(100vh - 250px)', overflowY: 'auto', overflowX: 'hidden' }}>
              <ul>
                {sortedCriticalNews.map((news, index) => (
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
            <h2 className="text-lg font-bold mb-4 text-[#00D1FF]">Recent Updates</h2>
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
            <div className="scrollbar" style={{ maxHeight: 'calc(100vh - 250px)', overflowY: 'auto', overflowX: 'hidden' }}>
              <ul>
                {sortedRecentUpdates.map((update, index) => (
                  <li key={index} className="p-2 hover:bg-[#282F47] rounded">
                    <span className="text-sm text-gray-300">{update.title}</span>
                    <br />
                    <span className="text-xs text-gray-500">{update.date}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default EventsPage;