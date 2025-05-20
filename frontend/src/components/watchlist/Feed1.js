"use client";
import { useState, useEffect, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useWatchlist } from "@/context/WatchlistContext";
import FeedCVEBlock from "@/components/FeedCVEBlock";
import Sidebar from "@/components/Sidebar";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import axios from "axios";

const PAGE_LIMIT_OPTIONS = [10, 20, 30];
// const FEED_STATE_KEY = "feed_state";
// Add cache duration (5 minutes)
// const CACHE_DURATION = 5 * 60 * 1000;

function Feed() {
  // const router = useRouter();
  // const searchParams = useSearchParams();

  const { watchlist, fetchWatchlist, activeWatchlistIndex } = useWatchlist();

  // Add cache state
  // const [feedCache, setFeedCache] = useState({
  //   data: null,
  //   timestamp: 0,
  //   query: "",
  // });

  // Initialize state from sessionStorage or URL parameters
  const [feedState, setFeedState] = useState(() => {
    // Only run on client side
    // if (typeof window === "undefined") {
    //   return {
    //     limit: PAGE_LIMIT_OPTIONS[0],
    //     page: 1,
    //     selectedFilters: [],
    //     watchlistIndex: activeWatchlistIndex,
    //     showTab: "open",
    //   };
    // }

    // Try to get from sessionStorage first
    // const savedState = sessionStorage.getItem(FEED_STATE_KEY);
    // if (savedState) {
    //   try {
    //     return JSON.parse(savedState);
    //   } catch (e) {
    //     console.error("Failed to parse feed state from storage:", e);
    //   }
    // }

    // commented
    // Fall back to URL parameters if available
    // if (searchParams) {
    //   const urlLimit = searchParams.get("limit");
    //   const urlPage = searchParams.get("page");
    //   const urlFilters = searchParams.get("filters");
    //   const urlWatchlistIndex = searchParams.get("watchlistIndex");
    //   const urlShowTab = searchParams.get("showTab");

    //   return {
    //     limit: urlLimit ? parseInt(urlLimit) : PAGE_LIMIT_OPTIONS[0],
    //     page: urlPage ? parseInt(urlPage) : 1,
    //     selectedFilters: urlFilters
    //       ? JSON.parse(decodeURIComponent(urlFilters))
    //       : [],
    //     watchlistIndex: urlWatchlistIndex
    //       ? parseInt(urlWatchlistIndex)
    //       : 0,
    //     showTab: urlShowTab ? urlShowTab : "open",
    //   };
    // }

    // Default values
    return {
      limit: PAGE_LIMIT_OPTIONS[0],
      page: 1,
      selectedFilters: [],
      watchlistIndex: activeWatchlistIndex,
      showTab: "open",
    };
  });

  const { limit, page, selectedFilters, watchlistIndex, showTab } = feedState;

  const [vulnerabilityList, setVulnerabilityList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [totalPages, setTotalPages] = useState(1);
  const [isInitialized, setIsInitialized] = useState(false);
  const [selectedCves, setSelectedCves] = useState({});

  // Fetch watchlist data on mount
  useEffect(() => {
    fetchWatchlist().then(() => {
      setIsInitialized(true);
    });
  }, [fetchWatchlist]);
  const [sortBy, setSortBy] = useState("lowest-scores-first");
  const [currentIndex, setCurrentIndex] = useState(0);
  const handleSortByChange = (event) => {
    setSortBy(event.target.value);
  };

  const handleLimitChange = (event) => {
    updateState({ limit: event.target.value});
    // setLimit(event.target.value);
  };
  // Fetch CVEs when needed with caching
  useEffect(() => {
    const fetchFeedData = async () => {
      // console.log("this is feed, i repeat this is feed", activeWatchlistIndex);
      setFeedState({ watchlistIndex: activeWatchlistIndex });
      if (!watchlist?.watchlists?.length || !isInitialized) return;

      // Ensure watchlist index is valid
      const safeIndex = Math.min(
        watchlistIndex,
        Math.max(0, watchlist.watchlists.length - 1)
      );

      if (safeIndex !== watchlistIndex) {
        console.log("this is safe index", safeIndex);
        setFeedState({ watchlistIndex: safeIndex });
        return;
      }

      const currentWatchlist = watchlist.watchlists[safeIndex];

      // Create query key for caching
      const queryKey = JSON.stringify({
        watchlist: currentWatchlist.name,
        page,
        limit,
        filters: selectedFilters,
      });

      // Check if we have a valid cache
      const now = Date.now();
      // if (
      //   feedCache.data &&
      //   feedCache.query === queryKey &&
      //   now - feedCache.timestamp < CACHE_DURATION
      // ) {
      //   setVulnerabilityList(feedCache.data.data);
      //   setTotalPages(feedCache.data.pagination.pages);
      //   return;
      // }

      setLoading(true);
      setError(null);

      try {
        const token = localStorage.getItem("accessToken");
        if (!token) throw new Error("No authentication token found");

        // Build query params
        const params = new URLSearchParams({
          page,
          limit,
        });

        params.append("watchlist", currentWatchlist.name);

        // Always send the filters parameter as a JSON string, even if empty
        params.append("filters", JSON.stringify(selectedFilters));

        console.log("Sending API request with filters:", selectedFilters);

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

        const data = response.data.data;
        const pagination = response.data.pagination;

        // Filter CVEs into their respective status tables
        const openCves = data.filter((cve) => cve.status === "open");
        const resolvedCves = data.filter((cve) => cve.status === "resolved");
        const manhandledCves = data.filter((cve) => cve.status === "manhandled");
        const ignoredCves = data.filter((cve) => cve.status === "ignored");

        // Set the filtered data to state
        // setTableDataOpen(openCves);
        // setTableDataResolved(resolvedCves);
        // setTableDataManhandled(manhandledCves);
        // setTableDataIgnored(ignoredCves);

        // Calculate total pages for each tab
        // setTotalPagesOpen(Math.ceil(openCves.length / limit));
        // setTotalPagesResolved(Math.ceil(resolvedCves.length / limit));
        // setTotalPagesManhandled(Math.ceil(manhandledCves.length / limit));
        // setTotalPagesIgnored(Math.ceil(ignoredCves.length / limit));

        // Update cache
        setVulnerabilityList(response.data.data);
        setTotalPages(response.data.pagination.pages);
        // setFeedCache({
        //   data: response.data,
        //   timestamp: now,
        //   query: queryKey,
        // });
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
      }
    };

    fetchFeedData();
  }, [
    watchlist,
    limit,
    page,
    selectedFilters,
    activeWatchlistIndex,
    setFeedState,
    isInitialized,
    // feedCache,
  ]);

  // Handler functions
  const handleFilterChange = (e) => {
    const { value, checked } = e.target;
    const newFilters = checked
      ? [...selectedFilters, value]
      : selectedFilters.filter((f) => f !== value);

    setFeedState({ selectedFilters: newFilters, page: 1 });
  };

  const handleWatchlistChange = (index) => {
    console.log("what you thought was watchlist");
    setFeedState({
      watchlistIndex: activeWatchlistIndex,
      selectedFilters: [],
      page: 1,
    });
  };

  const handleTabChange = (tab) => {
    setFeedState({ showTab: tab });
  };

  const handleCveSelection = (cveId) => {
    setSelectedCves((prevSelectedCves) => {
      return { ...prevSelectedCves, [cveId]: !prevSelectedCves[cveId] };
    });
  };

  // Update URL when state changes
  useEffect(() => {
    console.log("inside the useEffect", activeWatchlistIndex);
    if (!isInitialized || typeof window === "undefined") return;

    const params = new URLSearchParams();
    params.set("page", page);
    params.set("limit", limit);
    params.set("watchlistIndex", activeWatchlistIndex);
    params.set("showTab", showTab);

    if (selectedFilters?.length > 0) {
      params.set(
        "filters",
        encodeURIComponent(JSON.stringify(selectedFilters))
      );
    }

    // router.replace(`?${params.toString()}`, { scroll: false });
  }, [
    page,
    limit,
    selectedFilters,
    activeWatchlistIndex,
    showTab,
     router,
    isInitialized,
    feedState,
  ]);

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      console.log("something happend");
      setFeedState({ page: newPage });
    }
  };

  const handleNextPage = () => {
    const currentPage = page;

    if (currentPage < totalPages) {
      setFeedState({ page: currentPage + 1});
    }
  };

  const handlePrevPage = () => {
    const currentPage = getCurrentPage();

    if (currentPage > 1) {
      setFeedState({ page: currentPage - 1 });
    }
  };

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
    <div className="flex flex-col w-full mx-10">
      {/* Title */}
      <div className="flex justify-center w-full mb-4">
        <h1 className="text-2xl font-bold">Feed</h1>
      </div>
  
      
  
      {/* Columns */}
      <div className="flex flex-row w-full">
        {/* Left-hand sidebar */}
        <Sidebar>
          {/* Watchlist selector */}
          <div className="flex flex-col space-y-2">
            <h2 className="text-lg font-bold">Watchlist</h2>
            <select
              value={activeWatchlistIndex}
              onChange={(e) => handleWatchlistChange(Number(e.target.value))}
              className="bg-background border rounded-md px-3 py-2"
            >
              {watchlist.watchlists.map((wl, index) => (
                <option key={index} value={index}>
                  {wl.name}
                </option>
              ))}
            </select>
          </div>
        </Sidebar>
  
        {/* Main content area */}
        <div className="flex-1">
          {/* Sorting, filtering, and items per page */}
      <div className="flex justify-between w-full mb-4 pl-4">
        <div className="flex flex-row space-x-4">
          {/* Sorting options */}
          <div className="flex flex-col space-y-2">
          <h2 className="text-lg font-bold">Sort By</h2>
          <select
            value={sortBy}
            onChange={handleSortByChange}
            className="bg-background border rounded-md px-3 py-2"
          >
            <option value="lowest-scores-first">Lowest scores first</option>
            <option value="highest-scores-first">Highest scores first</option>
          </select>
        </div>
          
          {/* Items per page */}
          <div className="flex flex-col space-y-2">
            <h2 className="text-lg font-bold">Items per page</h2>
            <select
              value={limit}
              onChange={handleLimitChange}
              className="bg-background border rounded-md px-3 py-2"
            >
              {PAGE_LIMIT_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt} per page
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>  
          {/* Display CVEs */}
          <div className="flex justify-between m-4 mt-0">
            {/* Tabs */}
            <div className="flex flex-col">
              <div className="flex">
                {["open", "resolved", "ignored"].map((tab) => (
                  <button
                    key={tab}
                    className={`py-2 px-4 rounded-t-md transition duration-150 
                      ${showTab === tab ? "bg-[#00D1FF] text-[#2C3454]" : "bg-[#2C3454] text-[#00D1FF] hover:bg-[#E5E5E5]"}`}
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
                onClick={() => handlePrevPage}
                disabled={page === 1}
                className="px-2 py-1 rounded bg-[#282F47] disabled:opacity-50"
              >
                Prev
              </button>
              <span>
                  Page {feedState.page} of {totalPages}
              </span>
              <button
                  onClick={() => handleNextPage()}
                  disabled={page === totalPages}
                className="px-2 py-1 rounded bg-[#282F47] disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
  
          {/* Content based on loading state */}
          {loading ? (
            <div className="flex justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          ) : error ? (
            <div className="bg-red-100 text-red-700 p-4 rounded mb-4">
              {error}
            </div>
          ) : vulnerabilityList.length > 0 ? (
            <>
            <div className="scrollbar">
              {vulnerabilityList.map((cve, index) => (
                <div
                  key={index}
                  className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm p-4 mb-4 shadow-md relative"
                >
                  <div className="flex">
                    <input
                      type="checkbox"
                      className="mr-2"
                      checked={selectedCves[cve.cve_id] === true}
                      onChange={() => handleCveSelection(cve.cve_id)}
                      id={cve.cve_id}
                    />
                    <label htmlFor={cve.cve_id} className="flex-1">
                      <div>
                        <h3 className="text-lg font-bold text-[#00B7EF]">
                          {cve.cve_id}
                        </h3>
                        <p className="text-sm mx-2 overflow-wrap break-words text-gray-300">
                          {cve.description}
                        </p>
                      </div>
                    </label>
                  </div>
                </div>
              ))}
            </div>
            </>
          ) : ( 
                <div className="text-center py-8 text-muted-foreground">
                  No {showTab} vulnerabilities found ( 00 {vulnerabilityList.length} 00)
                </div>
              )}
      </div>
    </div>
      </div>
  );
}

export default Feed;
