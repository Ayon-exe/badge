// frontend/src/components/watchlist/Feed.js
"use client";
import { useState, useEffect, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useWatchlist } from "@/context/WatchlistContext";
import FeedCVEBlock from "@/components/FeedCVEBlock";
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
const FEED_STATE_KEY = "feed_state";
// Add cache duration (5 minutes)
const CACHE_DURATION = 5 * 60 * 1000;

function Feed() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { watchlist, fetchWatchlist } = useWatchlist();

  // Add cache state
  const [feedCache, setFeedCache] = useState({
    data: null,
    timestamp: 0,
    query: "",
  });

  // Initialize state from sessionStorage or URL parameters
  const [feedState, setFeedState] = useState(() => {
    // Only run on client side
    if (typeof window === "undefined") {
      return {
        limit: PAGE_LIMIT_OPTIONS[0],
        page: 1,
        selectedFilters: [],
        activeWatchlistIndex: 0,
      };
    }

    // Try to get from sessionStorage first
    const savedState = sessionStorage.getItem(FEED_STATE_KEY);
    if (savedState) {
      try {
        return JSON.parse(savedState);
      } catch (e) {
        console.error("Failed to parse feed state from storage:", e);
      }
    }

    // Fall back to URL parameters if available
    if (searchParams) {
      const urlLimit = searchParams.get("limit");
      const urlPage = searchParams.get("page");
      const urlFilters = searchParams.get("filters");
      const urlWatchlistIndex = searchParams.get("watchlistIndex");

      return {
        limit: urlLimit ? parseInt(urlLimit) : PAGE_LIMIT_OPTIONS[0],
        page: urlPage ? parseInt(urlPage) : 1,
        selectedFilters: urlFilters
          ? JSON.parse(decodeURIComponent(urlFilters))
          : [],
        activeWatchlistIndex: urlWatchlistIndex
          ? parseInt(urlWatchlistIndex)
          : 0,
      };
    }

    // Default values
    return {
      limit: PAGE_LIMIT_OPTIONS[0],
      page: 1,
      selectedFilters: [],
      activeWatchlistIndex: 0,
    };
  });

  const { limit, page, selectedFilters, activeWatchlistIndex } = feedState;

  const [vulnerabilityList, setVulnerabilityList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [totalPages, setTotalPages] = useState(1);
  const [isInitialized, setIsInitialized] = useState(false);

  // Update state helper function
  const updateState = useCallback((newPartialState) => {
    setFeedState((prevState) => {
      const newState = { ...prevState, ...newPartialState };
      // Save to sessionStorage
      if (typeof window !== "undefined") {
        sessionStorage.setItem(FEED_STATE_KEY, JSON.stringify(newState));
      }
      return newState;
    });
  }, []);

  // Fetch watchlist data on mount
  useEffect(() => {
    fetchWatchlist().then(() => {
      setIsInitialized(true);
    });
  }, [fetchWatchlist]);

  // Fetch CVEs when needed with caching
  useEffect(() => {
    const fetchFeedData = async () => {
      if (!watchlist?.watchlists?.length || !isInitialized) return;

      // Ensure watchlist index is valid
      const safeIndex = Math.min(
        activeWatchlistIndex,
        Math.max(0, watchlist.watchlists.length - 1)
      );

      if (safeIndex !== activeWatchlistIndex) {
        updateState({ activeWatchlistIndex: safeIndex });
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
      if (
        feedCache.data &&
        feedCache.query === queryKey &&
        now - feedCache.timestamp < CACHE_DURATION
      ) {
        setVulnerabilityList(feedCache.data.data);
        setTotalPages(feedCache.data.pagination.pages);
        return;
      }

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

        setVulnerabilityList(response.data.data);
        setTotalPages(response.data.pagination.pages);

        // Update cache
        setFeedCache({
          data: response.data,
          timestamp: now,
          query: queryKey,
        });
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
    updateState,
    isInitialized,
    feedCache,
  ]);

  // Handler functions
  const handleFilterChange = (e) => {
    const { value, checked } = e.target;
    const newFilters = checked
      ? [...selectedFilters, value]
      : selectedFilters.filter((f) => f !== value);

    updateState({ selectedFilters: newFilters, page: 1 });
  };

  const handleWatchlistChange = (index) => {
    updateState({
      activeWatchlistIndex: index,
      selectedFilters: [],
      page: 1,
    });
  };
  // Update URL when state changes
  useEffect(() => {
    if (!isInitialized || typeof window === "undefined") return;

    const params = new URLSearchParams();
    params.set("page", page);
    params.set("limit", limit);
    params.set("watchlistIndex", activeWatchlistIndex);

    if (selectedFilters.length > 0) {
      params.set(
        "filters",
        encodeURIComponent(JSON.stringify(selectedFilters))
      );
    }

    router.replace(`?${params.toString()}`, { scroll: false });
  }, [
    page,
    limit,
    selectedFilters,
    activeWatchlistIndex,
    router,
    isInitialized,
  ]);

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      updateState({ page: newPage });
    }
  };

  const handleLimitChange = (e) => {
    updateState({
      limit: Number(e.target.value),
      page: 1,
    });
  };

  useEffect(() => {
    const handleFeedReset = () => {
      updateState({ page: 1, activeWatchlistIndex: 0 });
    };

    // Add event listener
    window.addEventListener("feedReset", handleFeedReset);

    // Cleanup
    return () => {
      window.removeEventListener("feedReset", handleFeedReset);
    };
  }, [updateState]);

  // Add this useEffect hook after your other useEffect hooks to handle the reset event
  useEffect(() => {
    const handleFeedReset = (event) => {
      // Reset to default state, either using values from the event or defaults
      const defaults = event.detail || {
        page: 1,
        limit: 10,
        selectedFilters: [],
        activeWatchlistIndex: 0,
      };

      // Force reset all states
      updateState(defaults);

      // Clear the cache to force a fresh data fetch
      setFeedCache({
        data: null,
        timestamp: 0,
        query: "",
      });

      console.log(
        "Feed reset event received - resetting to defaults:",
        defaults
      );
    };

    // Add event listener for feed reset
    window.addEventListener("feedReset", handleFeedReset);

    // Cleanup
    return () => {
      window.removeEventListener("feedReset", handleFeedReset);
    };
  }, [updateState]);

  return (
    <div className="flex flex-row w-full mx-10">
      <div className="items-center justify-center">
        {error && !loading && (
          <div className="bg-destructive/10 text-destructive px-4 py-2 rounded-md mb-4">
            {error}
          </div>
        )}

        {/* Filter, Watchlist, and Items per page selection */}
        <div className="flex flex-row content-center space-x-4 my-4">
          {/* Filter checkboxes (from selected watchlist) */}
          <div className="flex space-x-4">
            <Select
              value={selectedFilters}
              onValueChange={(value) => {
                // If the user clicks on an already selected value, deselect it
                if (selectedFilters.includes(value)) {
                  updateState({
                    selectedFilters: selectedFilters.filter(
                      (filter) => filter !== value
                    ),
                    page: 1,
                  });
                } else {
                  // Otherwise, add the selection to the array
                  updateState({
                    selectedFilters: [...selectedFilters, value],
                    page: 1,
                  });
                }
              }}
            >
              <SelectTrigger className="w-[180px]">
                <SelectValue
                  placeholder={
                    selectedFilters.length > 0
                      ? `${selectedFilters.length} filter${
                          selectedFilters.length > 1 ? "s" : ""
                        } selected`
                      : "Filter by items"
                  }
                />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {watchlist.watchlists[activeWatchlistIndex]?.items.map(
                    (item, idx) => {
                      const labelValue =
                        item.vendor?.trim() || item.product?.trim();
                      return (
                        <SelectItem key={idx} value={labelValue}>
                          <div className="flex items-center gap-2">
                            <input
                              type="checkbox"
                              checked={selectedFilters.includes(labelValue)}
                              onChange={(e) => {
                                e.stopPropagation();
                                // Use the same logic as the onValueChange handler
                                if (selectedFilters.includes(labelValue)) {
                                  updateState({
                                    selectedFilters: selectedFilters.filter(
                                      (filter) => filter !== labelValue
                                    ),
                                    page: 1,
                                  });
                                } else {
                                  updateState({
                                    selectedFilters: [
                                      ...selectedFilters,
                                      labelValue,
                                    ],
                                    page: 1,
                                  });
                                }
                              }}
                            />
                            <span>{labelValue}</span>
                          </div>
                        </SelectItem>
                      );
                    }
                  )}
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>

          {/* Watchlist selector */}
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

          {/* Items per page */}
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

        {/* Display CVEs */}
        <div className="items-start w-full">
          {loading ? (
            <div className="flex justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          ) : vulnerabilityList.length > 0 ? (
            <>
              {/* Pagination */}
              <div className="flex justify-center gap-2 mt-6">
                <button
                  onClick={() => handlePageChange(page - 1)}
                  disabled={page === 1}
                  //for blue buttons
                  className="ml-2 px-2 w-24 py-1 bg-blue-500 text-white rounded hover:bg-blue-600"
                  //for white buttons
                  //className="px-4 py-2 border rounded-md disabled:opacity-50"
                >
                  Previous
                </button>
                <span className="px-4 py-2">
                  Page {page} of {totalPages}
                </span>
                <button
                  onClick={() => handlePageChange(page + 1)}
                  disabled={page === totalPages}
                  //for blue buttons
                  className="ml-2 px-2 w-24 py-1 bg-blue-500 text-white rounded hover:bg-blue-600"
                  //for white buttons
                  //className="px-4 py-2 border rounded-md disabled:opacity-50"
                >
                  Next
                </button>
              </div>

              {vulnerabilityList.map((cve, index) => (
                <div
                  key={index}
                  className="flex flex-row items-center space-x-4 mb-4"
                >
                  <p className="text-xl text-muted-foreground">
                    {(page - 1) * limit + index + 1}.
                  </p>
                  <FeedCVEBlock key={cve.cve_id} data={cve} />
                </div>
              ))}

              {/* Pagination */}
              <div className="flex justify-center gap-2 mt-6">
                <button
                  onClick={() => handlePageChange(page - 1)}
                  disabled={page === 1}
                  //for blue buttons
                  className="ml-2 px-2 w-24 py-1 bg-blue-500 text-white rounded hover:bg-blue-600"
                  //for white buttons
                  //className="px-4 py-2 border rounded-md disabled:opacity-50"
                >
                  Previous
                </button>
                <span className="px-4 py-2">
                  Page {page} of {totalPages}
                </span>
                <button
                  onClick={() => handlePageChange(page + 1)}
                  disabled={page === totalPages}
                  //for blue buttons
                  className="ml-2 px-2 w-24 py-1 bg-blue-500 text-white rounded hover:bg-blue-600"
                  //for white buttons
                  //className="px-4 py-2 border rounded-md disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              No vulnerabilities found.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Feed;
