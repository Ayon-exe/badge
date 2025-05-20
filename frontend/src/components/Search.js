"use client";
import {Loader2,Bookmark, X } from "lucide-react";
import { useState, useEffect } from "react";
import {Card,CardContent,} from "@/components/ui/card";
import axios from "axios";

const Search = () => {
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [isSearchFocused, setIsSearchFocused] = useState(false);

  useEffect(() => {
    const fetchResults = async () => {
      if (!searchQuery.trim()) {
        setSearchResults([]);
        return;
      }

      try {
        const response = await axios.get(
          `${
            process.env.SERVER_URL
          }/api/cve/autocomplete?q=${encodeURIComponent(searchQuery)}`
        );
        if (response.data) {
          const results = response.data;
          const vendors = results.vendors.map((vendor) => ({
            title: vendor,
            description: "",
            date: "",
            company: "",
            rate: "",
            location: "",
            tags: [],
          }));
          const products = results.products.map((product) => ({
            title: product,
            description: "",
            date: "",
            company: "",
            rate: "",
            location: "",
            tags: [],
          }));
          const cveIds = results.cveIds.map((cveId) => ({
            title: cveId,
            description: "",
            date: "",
            company: "",
            rate: "",
            location: "",
            tags: [],
          }));
          setSearchResults([...vendors, ...products, ...cveIds]);
        }
      } catch (err) {
        console.error(err);
      }
    };

    const debounceTimer = setTimeout(fetchResults, 300);
    return () => clearTimeout(debounceTimer);
  }, [searchQuery]);

  const handleSearchFocus = () => {
    setIsSearchFocused(true);
  };

  const handleSearchBlur = () => {
    setIsSearchFocused(false);
  };

  return (
    <div>
      <div className={`flex justify-center items-center py-4 ${isSearchFocused ? 'hidden' : ''}`}>
        <img
          src="https://static.wixstatic.com/media/e48a18_c949f6282e6a4c8e9568f40916a0c704~mv2.png/v1/crop/x_0,y_151,w_1920,h_746/fill/w_203,h_79,fp_0.50_0.50,q_85,usm_0.66_1.00_0.01,enc_auto/For%20Dark%20Theme.png"
          className=""
          alt="DeepCytes Logo"
        />
      </div>
      <div className={`search-container pb-10 ${isSearchFocused ? 'slide-up' : ''}`}>
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onFocus={handleSearchFocus}
          onBlur={handleSearchBlur}
          placeholder="Search Products, Vendors or CVE's...."
          className="search-input focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
      </div>
      <div className={`flex flex-wrap justify-center gap-4 ${isSearchFocused ? 'slide-up-results show' : 'slide-up-results'}`}>
        {searchResults.map((result, index) => (
          <SearchResult key={index} result={result} />
        ))}
      </div>
    </div>
  );
};

const SearchResult = ({ result }) => {
  const [logo, setLogo] = useState(null);

  useEffect(() => {
    const fetchLogo = async () => {
      const response = await fetch(`https://logo.clearbit.com/${result.title}.com`);
      const logoUrl = response.url;
      setLogo(logoUrl);
    };
    fetchLogo();
  }, [result.company]);
  return (
    <Card className="rounded-3xl bg-white shadow-lg p-2 w-80 border-2 border-black">
      <Card className="bg-[#009DBD] rounded-3xl p-4 border-2 border-black">
        <div className="flex justify-between items-center">
          <span className="bg-white text-sm text-black px-3 py-1 border-2 border-black rounded-full font-bold">{result.date}</span>
          <div className="w-8 h-8 flex items-center justify-center bg-white border border-black rounded-full">
            <Bookmark className="w-5 h-5 text-black" />
          </div>
        </div>
        
        <CardContent className="py-4 px-0">
        <div className="flex justify-between items-center">
          <div>
            <p className="text-sm text-black font-bold">{result.company}</p>
            <h2 className="text-lg text-black font-bold">{result.title}</h2>
          </div>
          <div className="w-10 h-10 flex items-center justify-center bg-white border border-black rounded-full">
            {logo ? (
              <img src={logo} alt={result.company} className="w-8 h-8 rounded-full" />
            ) : (
              <X className="w-6 h-6 text-black" />
            )}
          </div>
        </div>

          <div className="flex flex-wrap gap-2 mt-4">
            {result.tags.map((tag, index) => (
              <span key={index} className="text-xs text-black px-2 py-1 rounded-full border border-black font-medium">{tag}</span>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-between items-center px-4 py-2">
        <div>
          <span className="text-lg text-black font-bold">{result.rate}</span>
          <p className="text-gray-500 text-sm mt-1">{result.location}</p>
        </div>
        <button className="bg-black text-white text-sm font-bold py-2 px-2 rounded-full">Details</button>
      </div>
    </Card>
  );
};

export default Search;