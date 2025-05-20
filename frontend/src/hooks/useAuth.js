import { useState, useEffect } from "react";
import axios from "axios";

const useAuth = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Fetch user details
  const fetchUser = async () => {
    const accessToken = localStorage.getItem("accessToken");
    if (!accessToken) {
      setUser(null);
      setLoading(false);
      return;
    }

    try {
      const response = await axios.get(
        `${process.env.SERVER_URL}/api/auth/me`,
        {
          headers: { Authorization: `Bearer ${accessToken}` },
        }
      );
      setUser(response.data.user);
    } catch (error) {
      console.error("Failed to fetch user:", error);

      // Handle expired accessToken
      if (error.response?.status === 401) {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
          await fetchUser(); // Retry fetching user
        } else {
          setUser(null);
        }
      }
    } finally {
      setLoading(false);
    }
  };

  // Refresh accessToken using the refreshToken
  const refreshAccessToken = async () => {
    const refreshToken = localStorage.getItem("refreshToken");
    if (!refreshToken) {
      console.error("No refresh token available");
      return false;
    }

    try {
      const response = await axios.post(
        `${process.env.SERVER_URL}/api/auth/refresh-token`,
        {
          refreshToken,
        }
      );
      const { accessToken } = response.data;

      // Save the new accessToken
      localStorage.setItem("accessToken", accessToken);
      return true;
    } catch (error) {
      console.error("Failed to refresh access token:", error);
      logout(); // Clear tokens on failure
      return false;
    }
  };

  // Logout function
  const logout = () => {
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
    setUser(null);
  };

  useEffect(() => {
    fetchUser(); // Fetch user on app load
  }, []);

  return { user, loading, fetchUser, logout };
};

export default useAuth;
