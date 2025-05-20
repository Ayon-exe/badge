import React, { useState, useEffect } from 'react';
import axios from 'axios';

const VersionAutocomplete = ({ product, onChange }) => {
  const [query, setQuery] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);

  useEffect(() => {
    const fetchSuggestions = async () => {
      if (!query.trim()) return;

      setLoading(true);
      try {
        const response = await axios.get(
          `${process.env.SERVER_URL}/api/cve/product/${product}/autocomplete?q=${encodeURIComponent(query)}`
        );

        if (response.data && Array.isArray(response.data.versions)) {
          setSuggestions(response.data.versions);
        } else {
          setSuggestions([]);
        }
      } catch (err) {
        console.error(err);
        setSuggestions([]);
      } finally {
        setLoading(false);
      }
    };

    const debounceTimer = setTimeout(fetchSuggestions, 200);
    return () => clearTimeout(debounceTimer);
  }, [query, product]);

  const handleInputChange = (event) => {
    setQuery(event.target.value);
    onChange(event.target.value);
    setShowSuggestions(true);
  };

  const handleVersionSelect = (version) => {
    setQuery(version);
    onChange(version);
    setShowSuggestions(false);
  };

  return (
    <div className="relative">
      <input
        type="text"
        className="bg-background border rounded-md px-2 py-1 text-sm"
        placeholder="Enter a version"
        value={query}
        onChange={handleInputChange}
      />
      {loading && (
        <div className="absolute top-0 left-0 w-full h-full bg-background opacity-50 flex justify-center items-center">
          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary" />
        </div>
      )}
      {showSuggestions && suggestions.length > 0 && (
        <div
          className="absolute top-full left-0 w-full bg-background border rounded-md p-2 z-10"
          style={{ zIndex: 10 }}
        >
          <ul>
            {suggestions.map((suggestion) => (
              <li key={suggestion} className="py-1">
                <button
                  className="text-sm"
                  onClick={() => handleVersionSelect(suggestion)}
                >
                  {suggestion}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default VersionAutocomplete;