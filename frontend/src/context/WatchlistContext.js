"use client";

import { createContext, useContext, useState, useCallback } from "react";
import axios from "axios";
// import { useToast } from "@/hooks/use-toast";
import { toast } from "react-toastify"; // Import toast

const WatchlistContext = createContext(null);

export function WatchlistProvider({ children }) {
  const [watchlist, setWatchlist] = useState({ username: "", watchlists: [] })
  const [watchlistStats, setWatchlistStats] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  // const { toast } = useToast()
  const [activeWatchlistIndex, setActiveWatchlistIndex] = useState(0);

  const fetchWatchlistStats  = useCallback(async (showToast = false) => {
    const token = localStorage.getItem('accessToken')
    if (!token) {
      setError("No authentication token found")
      toast.error("Token expired.")
      return
    }

    setLoading(true)
    setError("")
    
    try {
      const response = await axios.get(`${process.env.SERVER_URL}/api/watchlist-stats`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })
      setWatchlistStats(response.data)
      console.log("stats data", watchlistStats);
      if (showToast) {
        // toast({
        //   title: "Watchlist Stats Updated",
        //   description: "Your watchlist stats has been refreshed.",
        // })
      }
    } catch (err) {
      const errorMessage = err.response?.status === 401 
        ? "Session expired. Please login again."
        : "Failed to fetch watchlist"
      setError(errorMessage)
      if (err.response?.status === 401) {
        localStorage.removeItem('accessToken')
      }
      // toast({
      //   title: "Error",
      //   description: errorMessage,
      //   variant: "destructive"
      // })
      toast.error("Failed to load statistics.");
    } finally {
      setLoading(false)
    }
  }, [toast])

  const fetchWatchlist = useCallback(async (showToast = false) => {
    const token = localStorage.getItem('accessToken')
    if (!token) {
        setError("No authentication token found")
        toast.error("Token expired.")
      return false;
    }
    setLoading(true);
    setError("");

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
        await fetchWatchlistStats();
        setWatchlist(response.data);
        if (showToast) {
          // toast({
          //   title: "Watchlist Updated",
          //   description: "Your watchlist has been refreshed.",
          // });
        }
      } catch (err) {
        const errorMessage =
          err.response?.status === 401
            ? "Session expired. Please login again."
            : "Failed to fetch watchlist";
        setError(errorMessage);
        if (err.response?.status === 401) {
          localStorage.removeItem("accessToken");
        }
        // toast({
        //   title: "Error",
        //   description: errorMessage,
        //   variant: "destructive",
        // });
      toast.error("Failed to load list");
      } finally {
        setLoading(false);
      }
    },
    [fetchWatchlistStats, toast]
  );

  const createNewWatchlist = useCallback(
    async (watchlistName) => {
      const token = localStorage.getItem("accessToken");
      if (!token) {
      toast.error("Token expired");
        // toast({
        //   title: "Authentication Error",
        //   description: "Please login to add items to your watchlist",
        //   variant: "destructive",
        // });
        return false;
      }

      console.log("inside the server call", watchlistName);
      try {
        await axios.post(
          `${process.env.SERVER_URL}/api/watchlist`,
          {
            watchlist: watchlistName,
          },
          {
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        toast.success(`${watchlistName} created.`);
        await fetchWatchlist();
        return true;
      } catch (error) {
        // toast({
        //   title: "Error",
        //   description: "Failed to add to watchlist. Please try again.",
        //   variant: "destructive",
        //});
        toast.error(`Failed to create ${watchlistName}.`);
        return false;
      }
    },
    [fetchWatchlist, toast]
  );

  const addToWatchlist = useCallback(
    async (type, value, watchlistName, version) => {
      const token = localStorage.getItem("accessToken");
      if (!token) {
        // toast({
        //   title: "Authentication Error",
        //   description: "Please login to add items to your watchlist",
        //   variant: "destructive",
        // });
      toast.error("Token Expired");
        return false;
      }

      try {
        const response = await axios.post(
          `${process.env.SERVER_URL}/api/watchlist/item`,
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

        await fetchWatchlist();
        toast.success(`${value} Added`);
        return true;
        // if (response.success === 200) {

        //   toast({
        //     title: "Success",
        //     description: response.data.message,
        //   });

        // }

        // return false;
      } catch (error) {
        // toast({
        //   title: "Error",
        //   description:
        //     error.response?.data?.message || "Failed to add item to watchlist",
        //   variant: "destructive",
        // });
      toast.error(`Failed to Add ${type}`);
        return false;
      }
    },
    [fetchWatchlist, toast]
  );

  const removeFromWatchlist = useCallback(
    async (type, value, watchlistName) => {
      const token = localStorage.getItem("accessToken");
      if (!token) {
        // toast({
        //   title: "Authentication Error",
        //   description: "Please login to remove items from your watchlist",
        //   variant: "destructive",
        // });
        toast.error("Token expired");
        return false;
      }

      try {
        const response = await axios.delete(
          `${process.env.SERVER_URL}/api/watchlist/item`, 
          {
            data: {
              [type]: value,
              watchlist: watchlistName,
            },
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          });
        toast.success(`${value} Removed`);

        await fetchWatchlist();
        return true;
      } catch (error) {
        // toast({
        //   title: "Error",
        //   description: "Failed to remove from watchlist. Please try again.",
        //   variant: "destructive",
        // });
        toast.error(`Failed to remove ${type}`);
        return false;
      }
    },
    [fetchWatchlist, toast]
  );

  const removeWatchlist = useCallback(
    async (watchlistName) => {
      const token = localStorage.getItem("accessToken");
      if (!token) {
        //toast({
        //  title: "Authentication Error",
        //  description: "Please login to remove items from your watchlist",
        //  variant: "destructive",
        //});
        toast.error("Token expired.")
        return false;
      }

      try {
        await axios.delete(`${process.env.SERVER_URL}/api/watchlist`, {
          data: {
            watchlist: watchlistName,
          },
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });

        toast.success(`Removed ${watchlistName}`);
        await fetchWatchlist();
        return true;
      } catch (error) {
        // toast({
        //   title: "Error",
        //   description: "Failed to remove from watchlist. Please try again.",
        //   variant: "destructive",
        // });
        toast.error(`Failed to remove ${watchlistName}`);
        return false;
      }
    },
    [fetchWatchlist,  toast]
  );

  const updateWatchlist = useCallback(
    async (watchlistName, newWatchlistName) => {
      const token = localStorage.getItem("accessToken");
      if (!token) {
        // toast({
        //   title: "Authentication Error",
        //   description: "Please login to rename your watchlist",
        //   variant: "destructive",
        // });
        toast.error("Token expired.")
        return false;
      }

      try {
        await axios.put(
          `${process.env.SERVER_URL}/api/watchlist`,
          {
            watchlist: watchlistName,
            newWatchlist: newWatchlistName,
          },
          {
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        toast.success(`Renamed ${watchlistName} to ${newWatchlistName}`);
        await fetchWatchlist();
        return true;
      } catch (error) {
        // toast({
        //   title: "Error",
        //   description: "Failed to rename to watchlist. Please try again.",
        //   variant: "destructive",
        // });
        toast.error(`Failed to rename ${watchlistName}`);
        return false;
      }
    },
    [fetchWatchlist, toast]
  );

  const value = {
    watchlist,
    watchlistStats,
    loading,
    error,
    fetchWatchlist,
    fetchWatchlistStats,
    addToWatchlist,
    removeFromWatchlist,
    activeWatchlistIndex,
    setActiveWatchlistIndex,
    updateWatchlist,
    createNewWatchlist,
    removeWatchlist,
  };

  return (
    <WatchlistContext.Provider value={value}>
      {children}
    </WatchlistContext.Provider>
  );
}

export const useWatchlist = () => {
  const context = useContext(WatchlistContext);
  if (!context) {
    throw new Error("useWatchlist must be used within a WatchlistProvider");
  }
  return context;
};
