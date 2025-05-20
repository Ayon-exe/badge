import React, { useState, useEffect, useCallback } from 'react';
import { useWatchlist } from '@/context/WatchlistContext';
import { useSearchParams, useRouter } from 'next/navigation';
import {   ChevronDown,
  ChevronUp, 
  ChevronLeft, 
  ChevronRight, 
  Check, 
  Loader2,
  CircleFadingArrowUp } from 'lucide-react';
import axios from 'axios';
import { toast } from 'react-toastify';
import FeedCVEBlock from '@/components/FeedCVEBlock';
import Link from "next/link";
import { updateProductVersion } from '@/lib/fetch';
import { DateSelector } from "@/components/DateSelector";
import VersionAutocomplete from './VersionAutocomplete';

const PAGE_LIMIT_OPTIONS = [10, 20, 30];

function Feed() {
  const router = useRouter();
  //For changeing the bias of cve element split
  const [widthPercentage, setWidthPercentage] = useState(62);

  const [selectedYear, setSelectedYear] = useState("all");
  const [selectedMonth, setSelectedMonth] = useState("all"); 
  const [selectedSortBy, setSelectedSortBy] = useState("publishDate");
  const [selectedOrder, setSelectedOrder] = useState("desc");

  const { watchlist, fetchWatchlist, activeWatchlistIndex, setActiveWatchlistIndex } = useWatchlist();
  const searchParams = useSearchParams();
  
  const tabParam = searchParams.get('tab');

  const [showTab, setShowTab] = useState("open");
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [sortBy, setSortBy] = useState("Default");
  const [limit, setLimit] = useState(PAGE_LIMIT_OPTIONS[0]);
  const [vulnerabilityList, setVulnerabilityList] = useState([]);
  const [isInitialized, setIsInitialized] = useState(false);
  const [selectedFilters, setSelectedFilters] = useState([]);
  const [selectedCves, setSelectedCves] = useState({});
  const [showMoveOptions, setShowMoveOptions] = useState(false);
  const [refresh, setRefresh] = useState(false);
  const [vendorsList, setVendorsList] = useState([]);
  const [filterOpen, setFilterOpen] = useState(false);

  const [selectedItems, setSelectedItems] = useState([]);
  const [updateClicked, setUpdateClicked] = useState({});
  const [newItem, setNewItem] = useState({});
  const [showSuggestionsForUpdate, setShowSuggestionsForUpdate] = useState({});

    
  const handleVersionUpgrade = async (productName, watchlistName, version) => {
    const type = 'product';
    const response = 
      await updateProductVersion(type, productName, watchlistName, version);
  }

  // Filter control states (used by dropdowns and filter button)
  const [filterParams, setFilterParams] = useState({
    year: selectedYear,
    month: selectedMonth,
    sortBy: selectedSortBy,
    order: selectedOrder,
    limit: limit,
  });

  // Add this to your component, possibly in a useEffect hook
useEffect(() => {
  // Initialize filter dropdown for mobile
  const filterButton = document.querySelector('.md\\:hidden button');
  const filterContent = document.getElementById('filter-content');
  
  if (filterButton && filterContent) {
    filterButton.addEventListener('click', () => {
      filterContent.classList.toggle('hidden');
    });
  }
  
  // Clean up event listener
  return () => {
    if (filterButton) {
      filterButton.removeEventListener('click', () => {
        filterContent.classList.toggle('hidden');
      });
    }
  };
}, []);

  // Update showTab when URL parameter changes
  useEffect(() => {
    if (tabParam && ['open', 'resolved', 'ignored', 'Vendors'].includes(tabParam)) {
      setShowTab(tabParam);
    }
  }, [tabParam]);

  // Apply date filters when they change
  useEffect(() => {
    // Only trigger a refresh if the component is already initialized
    if (isInitialized) {
      setPage(1); // Reset to first page when filters change
      setRefresh(true);
    }
  }, [selectedYear, selectedMonth]);

  // Monitor selected CVEs to show/hide move options
  useEffect(() => {
    const fetchFeedData = async () => {
      const currentWatchlist = watchlist.watchlists[activeWatchlistIndex];
      console.log("requesting data for", currentWatchlist);
      console.log("active on ", activeWatchlistIndex);

      setLoading(true);
      setError(null);

      try {
        const token = localStorage.getItem("accessToken");
        if (!token) throw new Error("No authentication token found");

        console.log("items", selectedItems);

        if (selectedItems?.length > 0) {
          console.log(
            "filters",
            encodeURIComponent(JSON.stringify(selectedItems))
          );
        }

        let apiEndpoint = `${process.env.SERVER_URL}/api/feed`;
        const params = new URLSearchParams();
        params.set("page", page);
        params.set("limit", limit);
        params.set("watchlist", currentWatchlist?.name);
        params.set("sort", sortBy);

        // Add date filters if they are not set to "all"
        if (selectedYear !== "all") {
          params.set("year", selectedYear);
        }
        
        if (selectedMonth !== "all") {
          params.set("month", selectedMonth);
        }

        // If vendors tab is selected, use the vendors-watchlists endpoint
        if (showTab === "Vendors") {
          apiEndpoint = `${process.env.SERVER_URL}/api/vendors-watchlists`;
        } else {
          // Only set status for non-vendor tabs
          params.set("status", showTab);
        }

        if (selectedItems?.length > 0) {
          params.set(
            "filters",
            JSON.stringify(selectedItems)
          );
        }

        const response = await axios.get(
          `${apiEndpoint}?${params.toString()}`,
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

        const data = response.data.data;
        const pagination = response.data.pagination;

        setVulnerabilityList(response.data.data);
        setTotalPages(response.data.pagination.pages);
        
        // Set vendors list if available in response (for Vendors tab)
        if (showTab === "Vendors" && response.data.vendorsFound) {
          setVendorsList(response.data.vendorsFound);
        }

        router.replace(`?${params.toString()}`, { scroll: false });

      } catch (err) {
        console.error("Error fetching feed:", err);
        setError(
          err.response?.data?.message ||
            err.message ||
            "Failed to load vulnerabilities"
        );
        setVulnerabilityList([]);
        setTotalPages(0);
      } finally {
        setLoading(false);
        setRefresh(false);
      }
    };

    fetchFeedData();
  }, [
    refresh,
    showTab,
    page,
    limit,
    selectedYear,
    selectedMonth,
    sortBy,
    activeWatchlistIndex,
    isInitialized,
    selectedItems
  ]);

  useEffect(() => {
    fetchWatchlist().then(() => {
      setIsInitialized(true);
    });
  }, [fetchWatchlist]);

  const handlePrevClick = () => {
    if (watchlist.watchlists.length > 0) {
      setActiveWatchlistIndex(() => ( (activeWatchlistIndex - 1 + watchlist.watchlists.length) % watchlist.watchlists.length));
      setSelectedItems([]);
    }
    setPage(1);
    setRefresh(true);
  };

  const handleNextClick = () => {
    if (watchlist.watchlists.length > 0) {
      setActiveWatchlistIndex(() => (activeWatchlistIndex + 1) % watchlist.watchlists.length);
      setSelectedItems([]);
    }
    setPage(1);
    setRefresh(true);
  };

  const handleItemClick = (item) => {
    if (selectedItems.includes(item)) {
      setSelectedItems(selectedItems.filter((i) => i !== item));
    console.log("if", selectedItems);
    } else {
      setSelectedItems([...selectedItems, item]);
    console.log("else", [...selectedItems, item]);
    }
    setRefresh(true);
  };

  const handleUpdateClick = (item) => {
    setUpdateClicked((prevUpdateClicked) => ({
      ...prevUpdateClicked,
      [item.product]: !prevUpdateClicked[item.product],
    }));
    setShowSuggestionsForUpdate((prevShowSuggestionsForUpdate) => ({
      ...prevShowSuggestionsForUpdate,
      [item.product]: true,
    }));
  };
  const handleUpdateVersion = async (item) => {
    const updatedItem = { ...item, version: newItem[item.product].trim() };
    const updatedWatchlist = watchlist.watchlists[activeWatchlistIndex].items.map((i) =>
      i.product === item.product ? updatedItem : i
    );
    watchlist.watchlists[activeWatchlistIndex].items = updatedWatchlist;
    setNewItem((prevNewItem) => ({ ...prevNewItem, [item.product]: '' }));
    setUpdateClicked((prevUpdateClicked) => ({ ...prevUpdateClicked, [item.product]: false }));
    console.log("item.product", item.product);
    console.log("watchlist.watchlists[activeWatchlistIndex].name", watchlist.watchlists[activeWatchlistIndex].name);
    console.log("newItem[item.product].trim()", newItem[item.product].trim());

    await updateProductVersion("product", item.product, watchlist.watchlists[activeWatchlistIndex].name, newItem[item.product].trim());
    setRefresh(true);
  };
  // const updateProductVersion = async (type, product, watchlistName, version) => {
  //   const response = await updateProductVersion(type, product, watchlistName, version);
  //   if (response.data && response.data.success) {
  //     toast.success("Product version updated successfully");
  //   } else {
  //     toast.error("Failed to update product version");
  //   }
  // };

  const handleAddItemClick = (item) => {
    const newItemObj = { product: newItem[item.product].trim() };
    watchlist.watchlists[activeWatchlistIndex].items.push(newItemObj);
    setSelectedItems([...selectedItems, newItemObj]);
    setNewItem((prevNewItem) => ({ ...prevNewItem, [item.product]: '' }));
    setUpdateClicked((prevUpdateClicked) => ({ ...prevUpdateClicked, [item.product]: false }));
  };

  const handleCveSelection = (cveId) => {
    setSelectedCves((prevSelectedCves) => {
      return { ...prevSelectedCves, [cveId]: !prevSelectedCves[cveId] };
    });
  };

  const toggleFilter = () => {
    setFilterOpen(!filterOpen);
    const filterContent = document.getElementById('filter-content');
    if (filterContent) {
      filterContent.classList.toggle('hidden');
    }
  };

  const handleMoveTo = (status) => {
    const selectedCveIds = Object.keys(selectedCves).filter((id) => selectedCves[id]);

    if (selectedCveIds.length === 0) {
      return;
    }

    updateCveStatus(selectedCveIds, status);

    setShowMoveOptions(false);
    setRefresh(true);
    setSelectedCves({});
  };

  // Handle date selection change
  const handleDateChange = (newDate) => {
    const [year, month] = newDate.split("-");
    setSelectedYear(year);
    setSelectedMonth(month);
  };

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
        toast.success(`${cveIds.length} CVE's moved to ${status}.`);
      } else {
        throw new Error("Status update failed");
      }
    } catch (err) {
      console.error("Error updating CVE status:", err);
      setError(err.message || "Failed to update CVE status");
    }
  };

  const handleNextPage = () => {
    if (page < totalPages) {
      setPage(page + 1);
    }
  };

  const handlePrevPage = () => {
    if (page > 1) {
      setPage(page - 1);
    }
  };

  const handleTabChange = (tab) => {
    setShowTab(tab);
    setPage(1);
    if (tab === "Vendors") {
      setSelectedItems([]);
    }
    // Clear selected CVEs when changing tabs
    setSelectedCves({});
  };

  //for unchecking checkboxes upon vendor tab click
  useEffect(() => {
    if (showTab === "Vendors") {
      setSelectedItems([]);
      // Reset checkboxes
      const checkboxes = document.querySelectorAll('input[type="checkbox"]');
      checkboxes.forEach((checkbox) => checkbox.checked = false);
    }
  }, [showTab]);

  const handleLimitChange = (event) => {
    setLimit(event.target.value);
    setPage(1);
  };

  const handleSortByChange = (event) => {
    setSortBy(event.target.value);
    setPage(1);
    setRefresh(true);
  };

  const formatEPSSScore = (score) => {
    if (isNaN(score) || !score && score !== 0) return "N/A";
    return (score * 100).toFixed(2).replace(/\.?0+$/, "") + " %";
  };

  const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    try {
      const date = new Date(dateString);
      return date
        .toLocaleDateString("en-GB", {
          month: "2-digit",
          day: "2-digit",
          year: "2-digit",
        })
        .replace(/\//g, "/");
    } catch (e) {
      return dateString;
    }
  };

  const truncateText = (text, maxLength) => {
    if (text.length > maxLength) {
      return text.substring(0, maxLength) + '...';
    }
    return text;
  };

  useEffect(() => {
    const hasSelectedCves = Object.values(selectedCves).some((value) => value);
    // Only show move options for non-vendor tabs
    setShowMoveOptions(hasSelectedCves && showTab !== "Vendors");
  }, [selectedCves, showTab]);

  return (
    <div className="w-full min-h-screen px-2 sm:px-2 md:px-0">
      <div className="w-full sm:w-full md:w-4/5 mx-auto px-0 sm:px-0 md:px-4">
        {/* Title */}
        <div className="flex justify-center w-full mb-4">
          <h1 className="text-2xl font-bold">Feed</h1>
        </div>
        
        {/* Columns - Stack vertically on mobile, side by side on desktop */}
        <div className="flex flex-col md:flex-col lg:flex-row w-full">
          {/* Left-hand sidebar - Convert to dropdown on mobile & tablet only */}
          <div className="w-full md:w-auto md:px-4 mb-4 md:mb-0">
            {/* Mobile/Tablet Dropdown Toggle - Only show on mobile & tablet */}
            <div className="lg:hidden w-full bg-slate-950/75 backdrop-blur-sm p-4 border border-white/20 rounded-lg shadow-lg mb-2 max-w-[100vw] overflow-hidden">
              <button 
                className="w-full flex justify-between items-center"
                onClick={toggleFilter}
              >
                <h2 className="text-lg font-bold">Filter by</h2>
                {filterOpen ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
              </button>
              
              {/* Filter content - Show/hide based on filterOpen state */}
              {filterOpen && (
                <div className="mt-4 w-full bg-slate-950/75 backdrop-blur-sm border-t border-white/20 pt-4">
                  {watchlist.watchlists.length > 0 ? (
                    <div className="flex items-center mb-4">
                      <button className="border rounded-lg px-3 py-2" onClick={() => handlePrevClick()}>
                        <ChevronLeft className="w-4 h-4" />
                      </button>
                      <h3 className="text-sm font-bold mx-2 break-words">
                        {watchlist.watchlists[activeWatchlistIndex].name}
                      </h3>
                      <button className="border rounded-lg px-3 py-2" onClick={() => handleNextClick()}>
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                  ) : (
                    <p>No watchlists available.</p>
                  )}
                  {watchlist.watchlists.length > 0 ? (
                    <div className="flex flex-col">
                      {showTab === "Vendors" ? (
                        <div>
                          {/* Vendors list */}
                          {vendorsList.length > 0 ? (
                            <ul className="max-h-[25vh] md:max-h-[60vh] overflow-y-auto">
                              {vendorsList.map((vendor, idx) => (
                                <li key={idx} className="flex flex-col mb-4">
                                  <div className="flex items-center">
                                    <input
                                      type="checkbox"
                                      value={vendor}
                                      onClick={() => handleItemClick(vendor)}
                                    />
                                    <span className="ml-2 break-words">{vendor}</span>
                                  </div>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p>No vendors available.</p>
                          )}
                        </div>
                      ) : (
                        <div>
                          {/* Products list */}
                          <ul className="max-h-[25vh] md:max-h-[60vh] overflow-y-auto w-full">
                          {watchlist.watchlists[activeWatchlistIndex].items.map((item, idx) => (
                            item.product ? (
                              <li key={idx} className="flex flex-col mb-4">
                                <div className="flex items-center">
                                  <input
                                    type="checkbox"
                                    value={item.product?.trim()}
                                    onClick={() => handleItemClick(item.product)}
                                    className="flex-shrink-0"
                                  />
                                  <span className="ml-2 break-words">{item.product?.trim()}</span>
                                </div>
                                {updateClicked[item.product] && (
                                  <div className="flex items-center mt-0 ml-4">
                                    <VersionAutocomplete
                                      product={item.product}
                                      defaultValue={item.version}
                                      onChange={(version) => {
                                        setNewItem((prevNewItem) => ({ ...prevNewItem, [item.product]: version }));
                                        setShowSuggestionsForUpdate((prevShowSuggestionsForUpdate) => ({
                                          ...prevShowSuggestionsForUpdate,
                                          [item.product]: false,
                                        }));
                                      }}
                                    />
                                    <button
                                      className="ml-2 p-1 bg-green-500 text-white rounded-lg"
                                      onClick={() => handleUpdateVersion(item)}
                                    >
                                      <Check className="w-4 h-4" />
                                    </button>
                                  </div>
                                )}
                              </li>
                            ) : null
                          ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p>No items available.</p>
                  )}
                </div>
              )}
            </div>
            
            {/* Desktop-only filter content - Always visible on desktop */}
            <div className="hidden lg:block w-full md:w-64 bg-slate-950/75 backdrop-blur-sm p-4 border border-white/20 rounded-lg shadow-lg overflow-hidden">
              <h2 className="text-lg font-bold mb-4">Filter by</h2>
              {watchlist.watchlists.length > 0 ? (
                <div className="flex items-center mb-4">
                  <button className="border rounded-lg px-3 py-2" onClick={() => handlePrevClick()}>
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <h3 className="text-sm font-bold mx-2 break-words">
                    {watchlist.watchlists[activeWatchlistIndex].name}
                  </h3>
                  <button className="border rounded-lg px-3 py-2" onClick={() => handleNextClick()}>
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              ) : (
                <p>No watchlists available.</p>
              )}
              {watchlist.watchlists.length > 0 ? (
                <div className="flex flex-col">
                  {showTab === "Vendors" ? (
                    <div>
                      {/* Vendors list */}
                      {vendorsList.length > 0 ? (
                        <ul className="max-h-[25vh] md:max-h-[60vh] overflow-y-auto">
                          {vendorsList.map((vendor, idx) => (
                            <li key={idx} className="flex flex-col mb-4">
                              <div className="flex items-center">
                                <input
                                  type="checkbox"
                                  value={vendor}
                                  onClick={() => handleItemClick(vendor)}
                                />
                                <span className="ml-2 break-words">{vendor}</span>
                              </div>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p>No vendors available.</p>
                      )}
                    </div>
                  ) : (
                    <div>
                      {/* Products list */}
                      <ul className="max-h-[25vh] md:max-h-[60vh] overflow-y-auto w-full">
                      {watchlist.watchlists[activeWatchlistIndex].items.map((item, idx) => (
                        item.product ? (
                          <li key={idx} className="flex flex-col mb-4">
                            <div className="flex items-center">
                              <input
                                type="checkbox"
                                value={item.product?.trim()}
                                onClick={() => handleItemClick(item.product)}
                                className="flex-shrink-0"
                              />
                              <span className="ml-2 break-words">{item.product?.trim()}</span>
                            </div>
                            {updateClicked[item.product] && (
                              <div className="flex items-center mt-0 ml-4">
                                <VersionAutocomplete
                                  product={item.product}
                                  defaultValue={item.version}
                                  onChange={(version) => {
                                    setNewItem((prevNewItem) => ({ ...prevNewItem, [item.product]: version }));
                                    setShowSuggestionsForUpdate((prevShowSuggestionsForUpdate) => ({
                                      ...prevShowSuggestionsForUpdate,
                                      [item.product]: false,
                                    }));
                                  }}
                                />
                                <button
                                  className="ml-2 p-1 bg-green-500 text-white rounded-lg"
                                  onClick={() => handleUpdateVersion(item)}
                                >
                                  <Check className="w-4 h-4" />
                                </button>
                              </div>
                            )}
                          </li>
                        ) : null
                      ))}
                      </ul>
                    </div>
                  )}
                </div>
              ) : (
                <p>No items available.</p>
              )}
            </div>
          </div>
    
          {/* Main content area */}
          <div className="flex-1">
            {/* Sorting, filtering, and items per page */}
            <div className="flex flex-col sm:flex-row sm:justify-between w-full mb-4 pl-0 md:pl-4">
              <div className="flex flex-col sm:flex-row gap-4 sm:gap-6">
                
                {/* Filtering options */}
                <div className="flex flex-col space-y-2">
                  <h2 className="text-lg font-bold">Published at:</h2>
                  <DateSelector
                    selectedDate={`${selectedYear}-${selectedMonth}`}
                    onChange={handleDateChange}
                  />
                </div>
    
                <div className="flex flex-row space-x-4">
                  {/* Sorting options */}
                  <div className="flex flex-col space-y-2 w-1/2 sm:w-auto">
                    <h2 className="text-lg font-bold">Sort By</h2>
                    <select
                      value={sortBy}
                      onChange={handleSortByChange}
                      className="bg-background border rounded-lg px-3 py-2 w-full sm:w-auto"
                    >
                      <option value="Default">Default</option>
                      <option value="lowest-scores-first">Lowest scores first</option>
                      <option value="highest-scores-first">Highest scores first</option>
                    </select>
                  </div>
    
                  {/* Items per page */}
                  <div className="flex flex-col space-y-2 w-1/2 sm:w-auto md:w-auto lg:w-auto">
                    <h2 className="text-lg font-bold">Items per page</h2>
                    <select
                      value={limit}
                      onChange={handleLimitChange}
                      className="bg-background border rounded-lg px-3 py-2 w-full sm:w-auto"
                    >
                      {PAGE_LIMIT_OPTIONS.map((opt) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Display CVEs */}
            <div className="flex flex-col sm:flex-row sm:justify-between my-0">
              {/* Tabs and Show Move Options */}
              <div className="flex flex-col mb-4 sm:mb-0">
                {/* Tabs - Scroll horizontally on mobile */}
                <div className="flex overflow-x-auto whitespace-nowrap pb-2">
                  {["open", "resolved", "ignored", "Vendors"].map((tab) => (
                    <button
                      key={tab}
                      className={`py-2 px-4 rounded-t-lg border border-white/20 transition duration-150 
                        ${showTab === tab ? "bg-[#00D1FF] text-[#000000] font-bold" : "bg-[#2C3454] text-[#1A1D23] hover:bg-[#E5E5E5]"}`}
                      onClick={() => handleTabChange(tab)}
                    >
                      {tab.charAt(0).toUpperCase() + tab.slice(1)}
                    </button>
                  ))}
                </div>
    
                {/* Show Move Options - Only for non-Vendors tabs */}
                {showMoveOptions && showTab !== "Vendors" && (
                  <div className="flex overflow-x-auto whitespace-nowrap pb-2">
                    <div style={{ display: 'flex', alignItems: 'center' }} className="bg-slate-950/75 border border-white/20 text-gray-300 text-sm hover:bg-slate-950/50 hover:text-gray-200 py-2 px-2">
                      <input
                        type="checkbox"
                        id="selectAll"
                        className="mr-2"
                        onChange={(e) => {
                          // Handle select all checkbox change
                          console.log(e.target.checked);
                        }}
                      />
                      <h2>Select All</h2>
                    </div>
                    <button
                      className="bg-slate-950/75 border border-white/20 text-gray-300 text-sm hover:bg-slate-950/50 hover:text-gray-200 py-2 px-2"
                      onClick={() => {
                        handleMoveTo("open");
                        handleTabChange(showTab); // Refresh the current tab
                      }}
                    >
                      Move to Open
                    </button>
                    <button
                      className="bg-slate-950/75 border border-white/20 text-gray-300 text-sm hover:bg-slate-950/50 hover:text-gray-200 py-2 px-2"
                      onClick={() => {
                        handleMoveTo("resolved");
                        handleTabChange(showTab); // Refresh the current tab
                      }}
                    >
                      Move to Resolved
                    </button>
                    <button
                      className="bg-slate-950/75 border border-white/20 text-gray-300 text-sm hover:bg-slate-950/50 hover:text-gray-200 py-2 px-2"
                      onClick={() => {
                        handleMoveTo("ignored");
                        handleTabChange(showTab); // Refresh the current tab
                      }}
                    >
                      Move to Ignored
                    </button>
                  </div>
                )}
              </div>
    
              {/* Pagination controls */}
              <div className="flex items-center justify-center sm:justify-end space-x-2 mb-4 sm:mb-0">
                <button
                  onClick={() => handlePrevPage()}
                  disabled={page === 1}
                  className="px-2 w-24 py-1 bg-blue-500 text-white rounded-lg disabled:opacity-50 hover:bg-blue-600"
                >
                  Prev
                </button>
                <span>
                  Page {page} of {totalPages}
                </span>
                <button
                  onClick={() => handleNextPage()}
                  disabled={page === totalPages}
                  className="px-2 w-24 py-1 bg-blue-500 text-white rounded-lg disabled:opacity-50 hover:bg-blue-600"
                >
                  Next
                </button>
              </div>
            </div>
    
            {/* Content based on loading state */}
<div className="bg-slate-950/75 backdrop-blur-sm p-2 rounded-tr-lg rounded-br-lg rounded-bl-lg shadow-md">
  {loading ? (
    <div className="space-y-4 p-4 animate-pulse">
      {/* Skeleton for CVE items - same height as real content */}
      {[1, 2, 3].map((item) => (
        <div 
          key={item}
          className="flex flex-col rounded-lg bg-slate-950/75 border-2 border-gray backdrop-blur-sm p-4 mb-4 shadow-md relative"
        >
          <div className="flex w-full">
            <div className="h-5 w-5 bg-gray-700 rounded mr-2 flex-shrink-0"></div>
            <div className="flex flex-col md:flex-row w-full md:divide-x md:divide-gray-600">
              {/* CVE description skeleton */}
              <div className="flex flex-col w-full md:w-3/5 md:pr-2">
                <div className="h-6 bg-gray-700 rounded w-32 mb-2"></div>
                <div className="h-4 bg-gray-700 rounded w-full mb-1"></div>
                <div className="h-4 bg-gray-700 rounded w-11/12 mb-1"></div>
                <div className="h-4 bg-gray-700 rounded w-4/5"></div>
              </div>
              {/* CVE details skeleton */}
              <div className="flex flex-col md:pl-4 mt-2 md:mt-0 md:w-2/5">
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-1 lg:grid-cols-1 xl:grid-cols-2 gap-2 md:gap-4 w-full">
                  <div className="flex justify-between items-center">
                    <div className="h-4 bg-gray-700 rounded w-16"></div>
                    <div className="h-6 bg-gray-700 rounded w-16 ml-2"></div>
                  </div>
                  <div className="flex justify-between items-center">
                    <div className="h-4 bg-gray-700 rounded w-12"></div>
                    <div className="h-6 bg-gray-700 rounded w-16 ml-2"></div>
                  </div>
                  <div className="flex justify-between items-center">
                    <div className="h-4 bg-gray-700 rounded w-20"></div>
                    <div className="h-4 bg-gray-700 rounded w-24 ml-2"></div>
                  </div>
                  <div className="flex justify-between items-center">
                    <div className="h-4 bg-gray-700 rounded w-20"></div>
                    <div className="h-4 bg-gray-700 rounded w-24 ml-2"></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  ) : error ? (
    <div className="bg-red-100 text-red-700 p-4 rounded-lg mb-4">
      {error}
    </div>
  ) : vulnerabilityList.length > 0 ? (
    <div>
      {vulnerabilityList.map((cve, index) => (
        <div
          key={index}
          className="flex flex-col rounded-lg bg-slate-950/75 border-2 border-gray backdrop-blur-sm p-4 mb-4 shadow-md relative hover:border-[#00B7EF] hover:border-2 transition duration-300"
        >
          <div className="flex w-full">
            <input
              type="checkbox"
              className="mr-2 flex-shrink-0"
              checked={selectedCves[cve.cve_id] === true}
              onChange={() => handleCveSelection(cve.cve_id)}
              id={cve.cve_id}
            />
            <label htmlFor={cve.cve_id} className="flex flex-col md:flex-row w-full md:divide-x md:divide-gray-600">
              {/* CVE description container - Made narrower on desktop */}
              <div className="flex flex-col w-full md:w-3/5 md:pr-2">
                <Link href={`/cve/${cve.cve_id}`}>
                  <h3 className="text-lg font-bold text-[#00B7EF]">
                    {cve.cve_id}
                  </h3>
                </Link>
                <p className="text-sm overflow-wrap break-words text-gray-300">
                  {truncateText(cve.description, 200)}
                </p>
              </div>
              {/* CVE details container - Made wider on desktop */}
              <div className="flex flex-col md:pl-4 mt-2 md:mt-0 md:w-2/5">
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-1 lg:grid-cols-1 xl:grid-cols-2 gap-2 md:gap-4 w-full">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-400">Max CVSS</span>
                    <span
                      className={`${ 
                      cve.cvss_score === "N/A"
                      ? "bg-[#8A8A8A33] text-white border-gray-700"
                      : cve.cvss_score >= 9
                      ? "bg-[#530006] text-[#FF5A65] border-[#530006]"
                      : cve.cvss_score >= 7
                      ? "bg-[#855e11] text-[#FDB52A] border-[#855e11]"
                      : cve.cvss_score >= 4
                      ? "bg-[#004122] text-[#14CA74] border-[#004122]"
                      : "bg-[#8A8A8A33] text-white border-gray-700"
                      } border px-3 py-1 rounded-lg text-sm ml-2 text-center min-w-[60px]`}
                      >
                      {cve?.cvss_score ? cve?.cvss_score : "N/A"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-400">EPSS</span>
                    <span
                      className={`${
                      !cve.epss?.epss_score && cve.epss?.epss_score !== 0
                      ? "bg-[#8A8A8A33] text-white border-gray-700"
                      : cve.epss.epss_score * 100 < 0.05
                      ? "bg-[#004122] text-[#14CA74] border-[#004122]"
                      : cve.epss.epss_score * 100 >= 0.05 &&
                       cve.epss.epss_score * 100 < 0.09
                      ? "bg-[#855e11] text-[#FDB52A] border-[#855e11]"
                      : cve.epss.epss_score * 100 >= 0.09
                      ? "bg-[#530006] text-[#FF5A65] border-[#530006]"
                      : "bg-[#8A8A8A33] text-white border-gray-700" 
                       } border px-3 py-1 rounded-lg text-sm ml-2 text-center inline-flex items-center whitespace-nowrap min-w-[70px]`}
                      >
                      {formatEPSSScore(cve?.epss?.epss_score ?? "N/A")}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-400">Published:</span>
                    <span className="text-sm ml-2">{formatDate(cve.published_at)}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-400">Updated:</span>
                    <span className="text-sm ml-2">{formatDate(cve.updated_at)}</span>
                  </div>
                </div>
              </div>
            </label>
          </div>
        </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                No {showTab} vulnerabilities found.
              </div>
            )}
          </div>
          {/* Pagination controls */}
          <div className="flex items-center justify-center mt-4 space-x-2">
            <button
              onClick={() => handlePrevPage()}
              disabled={page === 1}
              className="px-2 w-24 py-1 bg-blue-500 text-white rounded-lg disabled:opacity-50 hover:bg-blue-600"
            >
              Prev
            </button>
            <span>
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => handleNextPage()}
              disabled={page === totalPages}
              className="px-2 w-24 py-1 bg-blue-500 text-white rounded-lg disabled:opacity-50 hover:bg-blue-600"
            >
              Next
            </button>
          </div>
          </div>
        </div>
      </div>
    </div>
  );

}


export default Feed;
