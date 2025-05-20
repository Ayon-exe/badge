import React, { useState } from "react";

const CVEFilter = ({ onFilter }) => {
  const [year, setYear] = useState("");
  const [month, setMonth] = useState("");
  const [sortBy, setSortBy] = useState("publishDate:desc");

  const handleFilter = () => {
    onFilter({ year, month, sortBy });
  };

  return (
    <div className="mb-4 w-full">
      <div className="flex flex-col md:flex-row md:space-x-4 space-y-2 md:space-y-0 w-full">

        {/* Mobile only Year + Month stay inline */}
        <div className="flex flex-row gap-2 w-full md:flex-row md:gap-4 md:w-auto">
          <div className="w-1/2 md:w-auto max-w-xs">
            <label htmlFor="year" className="block font-medium text-white">
              Year
            </label>
            <select
              id="year"
              value={year}
              onChange={(e) => setYear(e.target.value)}
              className="bg-gray-800 text-white px-4 py-2 rounded-md w-full"
            >
              <option value="">All</option>
              {Array.from({ length: 5 }, (_, i) => 2020 + i).map((y) => (
                <option key={y} value={y}>
                  {y}
                </option>
              ))}
            </select>
          </div>

          <div className="w-1/2 md:w-auto max-w-xs">
            <label htmlFor="month" className="block font-medium text-white">
              Month
            </label>
            <select
              id="month"
              value={month}
              onChange={(e) => setMonth(e.target.value)}
              className="bg-gray-800 text-white px-4 py-2 rounded-md w-full"
            >
              <option value="">All</option>
              {Array.from({ length: 12 }, (_, i) => i + 1).map((m) => (
                <option key={m} value={m.toString().padStart(2, "0")}>
                  {new Date(0, m - 1).toLocaleString("default", {
                    month: "long",
                  })}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Rest stays like original */}
        <div className="w-full md:w-auto max-w-xs">
          <label htmlFor="sortBy" className="block font-medium text-white">
            Sort By
          </label>
          <select
            id="sortBy"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="bg-gray-800 text-white px-4 py-2 rounded-md w-full"
          >
            <option value="publishDate:desc">Latest</option>
            <option value="publishDate:asc">Oldest</option>
            <option value="cvss_score:desc">Highest CVSS</option>
            <option value="cvss_score:asc">Lowest CVSS</option>
          </select>
        </div>

        <div className="w-full md:w-auto self-end">
          <button
            onClick={handleFilter}
            className="bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700 transition-all w-full md:w-auto"
          >
            Filter
          </button>
        </div>

      </div>
    </div>
  );
};

export default CVEFilter;
