"use client";
import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import { Search } from "lucide-react";
import { useRouter } from "next/navigation";

function SearchBox() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showDropdown, setShowDropdown] = useState(false);
  const searchRef = useRef(null);
  const router = useRouter();

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (searchRef.current && !searchRef.current.contains(event.target)) {
        setShowDropdown(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    const fetchResults = async () => {
      if (!query.trim()) {
        setResults(null);
        setError("");
        return;
      }

      setLoading(true);
      try {
        const response = await axios.get(
          `${
            process.env.SERVER_URL
          }/api/cve/autocomplete?q=${encodeURIComponent(query)}`
        );
        if (response.data) {
          setResults(response.data);
          setError("");
          setShowDropdown(true);
        }
      } catch (err) {
        const errorMessage =
          err instanceof Error ? err.message : "Search failed";
        setError(errorMessage);
        setResults(null);
      } finally {
        setLoading(false);
      }
    };

    const debounceTimer = setTimeout(fetchResults, 300);
    return () => clearTimeout(debounceTimer);
  }, [query]);

  const handleSelect = (type, value) => {
    switch (type) {
      case "vendor":
        router.push(`/vendor/${encodeURIComponent(value)}`);
        break;
      case "product":
        router.push(`/product/${encodeURIComponent(value)}`);
        break;
      case "cve":
        router.push(`/cve/${encodeURIComponent(value)}`);
        break;
    }
    setShowDropdown(false);
    setQuery("");
  };

  return (
    <div ref={searchRef} className="relative flex flex-auto">
      <div className="relative">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search CVE ID, Product, or Vendor..."
          className="grow w-full sd:w-1/4 bg-[#1A1B2E] text-white placeholder-gray-400 rounded-lg pl-10 pr-4 py-2 focus:outline-hidden focus:ring-2 focus:ring-cyan-500"
          />
        <Search className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
      </div>

      {showDropdown && (query.trim() || loading || error) && (
        <div className="absolute w-full mt-10 bg-[#1A1B2E] rounded-lg shadow-lg border border-gray-800 z-50">
          {loading && (
            <div className="p-4 text-center">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-cyan-500 mx-auto"></div>
            </div>
          )}

          {error && <div className="p-4 text-red-500 text-sm">{error}</div>}

          {results && !loading && !error && (
            <div className="py-2">
              {results.vendors.slice(0, 5).length > 0 && (
                <div className="px-4 py-2">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase mb-2">
                    Vendors
                  </h3>
                  {results.vendors.slice(0, 5).map((vendor) => (
                    <button
                      key={vendor}
                      onClick={() => handleSelect("vendor", vendor)}
                      className="block w-full text-left px-4 py-2 text-white hover:bg-cyan-600 rounded-lg"
                    >
                      {vendor}
                    </button>
                  ))}
                </div>
              )}

              {results.products.slice(0, 5).length > 0 && (
                <div className="px-4 py-2">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase mb-2">
                    Products
                  </h3>
                  {results.products.slice(0, 5).map((product) => (
                    <button
                      key={product}
                      onClick={() => handleSelect("product", product)}
                      className="block w-full text-left px-4 py-2 text-white hover:bg-cyan-600 rounded-lg"
                    >
                      {product}
                    </button>
                  ))}
                </div>
              )}

              {results.cveIds.slice(0, 5).length > 0 && (
                <div className="px-4 py-2">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase mb-2">
                    CVE IDs
                  </h3>
                  {results.cveIds.slice(0, 5).map((cveId) => (
                    <button
                      key={cveId}
                      onClick={() => handleSelect("cve", cveId)}
                      className="block w-full text-left px-4 py-2 text-white hover:bg-cyan-600 rounded-lg"
                    >
                      {cveId}
                    </button>
                  ))}
                </div>
              )}
              <a class="px-4 text-xs font-semibold text-gray-400 uppercase mb-2" href="/search">
                See More
              </a>

              {!results.vendors.length &&
                !results.products.length &&
                !results.cveIds.length && (
                  <div className="px-4 py-2 text-gray-400 text-sm">
                    No results found
                  </div>
                )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default SearchBox;
