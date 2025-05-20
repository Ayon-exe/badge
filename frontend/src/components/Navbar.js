"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react"; // Retain for Google sessions if used elsewhere
import axios from "axios";
import SearchBox from "./SearchBox";
import LoginDialog from "./LoginDialog";
import SignupDialog from "./SignupDialog";
import { FaUserCircle } from "react-icons/fa"; // Default icon for missing profile picture
import { useAuthContext } from "./AuthContext";
import { useRouter } from "next/navigation"; // Next.js navigation hook
import {
  House,
  Menu,
  SquareActivity,
  LayoutDashboard,
  Calendar,
  Wrench,
  Newspaper,
  ShoppingBag,
  Gem,
} from "lucide-react";

function Navbar() {
  const { user, loading, logout } = useAuthContext();
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [isMoreDropdownOpen, setIsMoreDropdownOpen] = useState(false); // New dropdown state for "More"
  const [showAuthRequiredPopup, setShowAuthRequiredPopup] = useState(false);
  const dropdownRef = useRef(null);
  const moreDropdownRef = useRef(null); // Ref for More dropdown
  const { status } = useSession(); // for loading state
  const router = useRouter();

  // Handle signup rerouting
  const handleSignup = async (userData) => {
    try {
      const response = await axios.post("/api/auth/register", userData); // Ensure this hits the correct register endpoint
      if (response.status === 201) {
        const { token } = response.data;
        localStorage.setItem("authToken", token); // Save the token in localStorage
        await fetchUser(); // Re-fetch the user immediately
        router.push("/"); // Redirect to the homepage
      }
    } catch (error) {
      console.error("Signup failed", error);
    }
  };

  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const [isOverlayOpen, setIsOverlayOpen] = useState(false);

  const [isSidenavOpen, setIsSidenavOpen] = useState(false);

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen((prev) => !prev);
  };

  const handleSignOut = async () => {
    const accessToken = localStorage.getItem("accessToken");

    try {
      // Call the /logout API endpoint
      const response = await fetch(
        `${process.env.SERVER_URL}/api/auth/logout`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
          },
        }
      );

      if (response.ok) {
        console.log("Logged out successfully");
      } else {
        const errorData = await response.json();
        console.error(
          "Failed to log out:",
          errorData.message || "Unknown error"
        );
      }
    } catch (error) {
      console.error("Error logging out:", error);
    }

    // Clear tokens and user state
    logout();

    // Redirect to the homepage
    router.push("/");
  };

  const handleProfile = async (userData) => {
    router.push("/profile");
  };

  const handleAudit = async (userData) => {
    router.push("/audit");
  };

  const toggleDropdown = () => {
    setIsDropdownOpen((prev) => !prev);
  };

  // Toggle "More" dropdown
  const toggleMoreDropdown = () => {
    setIsMoreDropdownOpen((prev) => !prev);
  };

  const handleClickOutside = (event) => {
    // Close profile dropdown if clicking outside
    if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
      setIsDropdownOpen(false);
    }
    // Close more dropdown if clicking outside
    if (moreDropdownRef.current && !moreDropdownRef.current.contains(event.target)) {
      setIsMoreDropdownOpen(false);
    }
  };

  const handleFeedClick = () => {
    if (!user) {
      // Show authentication required popup
      setShowAuthRequiredPopup(true);
    } else {
      // Clear feed state from session storage before navigation
      if (typeof window !== "undefined") {
        sessionStorage.removeItem("feed_state");
        const resetEvent = new CustomEvent("feedReset", {
          detail: {
            page: 1,
            limit: 10,
            selectedFilters: [],
            activeWatchlistIndex: 0,
          },
        });
        window.dispatchEvent(resetEvent);
      }
      router.push("/feed");
    }
  };

  useEffect(() => {
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  const handleDashboardClick = () => {
    if (!user) {
      setShowAuthRequiredPopup(true);
    } else {
      router.push("/dashboard");
    }
  };

  const handleCloseAuthRequiredPopup = () => {
    setShowAuthRequiredPopup(false);
  };

  return (
    <>
      <nav className="bg-[#00011E] border-b-2 border-[#38C8F8] border-opacity-70 flex flex-wrap items-center">
        <div className="mx-auto flex flex-nowrap sm:flex-nowrap items-center justify-between">
          <div className="flex items-center justify-between w-full sm:w-auto">
            <div className="sm:hidden md:block lg:hidden">
              <button
                type="button"
                className="relative size-9 flex justify-center items-center gap-2 rounded-lg border border-gray-700 font-medium bg-[#00011E] text-gray-400 shadow-2xs hover:bg-gray-700/20 focus:outline-hidden focus:bg-gray-700/20 text-sm"
                onClick={() => setIsSidenavOpen(true)}
              >
                <Menu className="size-5" />
                <span className="sr-only">Open Menu</span>
              </button>
            </div>
            {/* Logo Always Visible */}
            <Link href="/">
              <img
                src="https://static.wixstatic.com/media/e48a18_c949f6282e6a4c8e9568f40916a0c704~mv2.png/v1/crop/x_0,y_151,w_1920,h_746/fill/w_203,h_79,fp_0.50_0.50,q_85,usm_0.66_1.00_0.01,enc_auto/For%20Dark%20Theme.png"
                className="mr-2 max-h-10"
                alt="DeepCytes Logo"
              />
            </Link>
          </div>

          {/* Desktop Menu Links */}
          <div className="hidden sm:block md:hidden lg:block flex-1">
            <div className="flex space-x-4 text-white font-medium justify-end">
              <Link
                href="/"
                className="hover:text-[#3DB5DA] transition-colors flex items-center gap-2"
              >
                {/* <House /> */}
                <span>Home</span>
              </Link>
              {/* <button
                onClick={handleDashboardClick}
                className="hover:text-[#3DB5DA] transition-colors flex items-center gap-2"
              >
                <LayoutDashboard />
                <span>Dashboard</span>
              </button> */}
              {/* <button
                onClick={handleFeedClick}
                className="hover:text-[#3DB5DA] transition-colors flex items-center gap-2"
              >
                <Newspaper />
                <span>Feed</span>
              </button> */}
              <Link
                href="/allbadges"
                className="hover:text-[#3DB5DA] transition-colors flex items-center gap-2"
              >
                {/* <ShoppingBag /> */}
                <span>All Badges</span>
              </Link>

              {/* More dropdown */}
              <div className="relative" ref={moreDropdownRef}>
                <button
                  onClick={toggleMoreDropdown}
                  className="hover:text-[#3DB5DA] transition-colors flex items-center gap-2 focus:outline-none"
                >
                  <span>More</span>
                </button>
                {isMoreDropdownOpen && (
                  <ul className="absolute right-0 mt-2 w-36 bg-white text-black rounded-lg shadow-md z-50">
                    <li>
                      <Link
                        href="/about"
                        onClick={() => setIsMoreDropdownOpen(false)}
                        className="block px-4 py-2 hover:bg-gray-200 rounded-t-lg"
                      >
                        About Us
                      </Link>
                    </li>
                    <li>
                      <Link
                        href="/contact"
                        onClick={() => setIsMoreDropdownOpen(false)}
                        className="block px-4 py-2 hover:bg-gray-200 rounded-b-lg"
                      >
                        Contact
                      </Link>
                    </li>
                  </ul>
                )}
              </div>
            </div>
          </div>

          {/* User Authentication */}
          <div className="flex items-center gap-4 whitespace-nowrap shrink-0 m-4">
            {status === "loading" ? (
              <p className="text-white">Loading...</p>
            ) : user ? (
              <div className="relative" ref={dropdownRef}>
                <button
                  onClick={toggleDropdown}
                  className="flex items-center space-x-2 text-white bg-[#1a1a4b] px-4 py-2 rounded-lg hover:bg-[#2b2b6b]"
                >
                  {user.profilePicture ? (
                    <img
                      src={user.profilePicture}
                      alt={user.name}
                      className="w-8 h-8 rounded-full object-cover"
                      onError={(e) =>
                        (e.currentTarget.src = "/default-avatar.png")
                      }
                    />
                  ) : (
                    <FaUserCircle className="w-8 h-8" />
                  )}
                  <span className="hidden sm:inline ">{user.name}</span>
                </button>
                {isDropdownOpen && (
                  <ul className="mt-2 w-36 bg-white text-black rounded-lg shadow-md z-50 absolute top-12 right-0">
                    <li className="bg-slate-200 rounded-lg">
                      <button
                        onClick={handleProfile}
                        className="block px-2 py-2 w-full text-left hover:bg-gray-400 transition-colors rounded-lg"
                      >
                        Profile
                      </button>
                    </li>
                    <li className="bg-slate-200 rounded-lg">
                      <button
                        onClick={handleAudit}
                        className="block px-2 py-2 w-full text-left hover:bg-gray-400 transition-colors rounded-lg"
                      >
                        Audit
                      </button>
                    </li>
                    <li className="bg-slate-200 rounded-lg">
                      <button
                        onClick={handleSignOut}
                        className="block px-2 py-2 w-full text-left hover:bg-gray-400 transition-colors rounded-lg"
                      >
                        Sign Out
                      </button>
                    </li>
                  </ul>
                )}
              </div>
            ) : (
              <div className="flex space-x-2 md:m-2">
                <LoginDialog />
              </div>
            )}
          </div>
        </div>

        {/* Mobile SideNav Menu */}
        <div
          className={`fixed top-0 left-0 h-full bg-black/50 backdrop-blur-sm z-50 overflow-x-hidden transition-all duration-500 ${
            isSidenavOpen ? "w-[250px]" : "w-0"
          }`}
        >
          <button
            className="absolute top-4 right-4 text-white text-4xl"
            onClick={() => setIsSidenavOpen(false)}
          >
            &times;
          </button>

          <div className="flex flex-col space-y-6 pt-16 pl-8">
            <Link
              href="/"
              onClick={() => setIsSidenavOpen(false)}
              className="text-gray-400 text-2xl hover:text-white"
            >
              Home
            </Link>

            {/* <button
              onClick={() => {
                handleFeedClick();
                setIsSidenavOpen(false);
              }}
              className="text-gray-400 text-2xl text-left hover:text-white"
            >
              Feed
            </button> */}

            <Link
              href="/allbadges"
              onClick={() => setIsSidenavOpen(false)}
              className="text-gray-400 text-2xl hover:text-white"
            >
              All Badges
            </Link>

            <Link
              href="/about"
              onClick={() => setIsSidenavOpen(false)}
              className="text-gray-400 text-2xl hover:text-white"
            >
              About Us
            </Link>
            <Link
              href="/Contact"
              onClick={() => setIsSidenavOpen(false)}
              className="text-gray-400 text-2xl hover:text-white"
            >
              Contact Us
            </Link>
          </div>
        </div>
      </nav>

      {/* Authentication Required Popup */}
      {showAuthRequiredPopup && (
        <div className="fixed inset-0 flex items-center justify-center z-50 backdrop-blur">
          <div className="bg-slate-950/30 backdrop-blur p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-bold mb-4">Authentication Required</h2>
            <p className="mb-4">You need to be authenticated to access this feature.</p>
            <div className="flex justify-end">
              <button
                onClick={handleCloseAuthRequiredPopup}
                className="bg-[#3DB5DA] text-white px-4 py-2 rounded-lg hover:bg-[#2b9dc0] transition-colors"
              >
                OK
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
export default Navbar;
