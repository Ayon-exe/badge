"use client";

import React, { useState, useEffect } from "react";
import { getProductVulnerabilityData } from "@/lib/fetch";
import CVEFilter from "./CVEFilter";
import CVEProduct from "./CVEProduct";

const CVEDataController = ({ product, version }) => {
  const [productName, setProductName] = useState("");
  const [versionName, setVersionName] = useState("");
  const [CVEData, setCVEData] = useState({
    vulnerabilities: [],
    pagination: { total: 0, page: 1, limit: 2, pages: 0 },
  });
  const [filters, setFilters] = useState({
    year: "",
    month: "",
    sortBy: "publishDate:desc",
  });

  useEffect(() => {
    const fetchData = async () => {
      const productNameStr = product.replaceAll("-", " ");
      const versionNameStr = version.replaceAll("-", " ");
      setProductName(productNameStr);
      setVersionName(versionNameStr);

      const data = await getProductVulnerabilityData(
        productNameStr,
        versionNameStr,
        filters.year,
        filters.month,
        filters.sortBy
      );
      setCVEData(data);
    };
    fetchData();
  }, [product, version, filters]);

  const handleFilter = (newFilters) => {
    setFilters(newFilters);
  };

  return (
    <div className="min-h-screen w-full flex justify-center items-center px-2 md:px-0">
      <div className="text-white justify-start bg-slate-950/30 flex flex-col mb-4 pt-4 overflow-x-hidden backdrop-blur-md shadow-lg rounded-lg w-full max-w-7xl">
        <div className="w-full px-4 md:px-7 shadow-lg bg-slate-950/30 py-4">
          {/* Make filters in one line on desktop, stack on mobile */}
          <div className="flex flex-col md:flex-row md:items-center md:space-x-6 space-y-4 md:space-y-0">
            <CVEFilter onFilter={handleFilter} />
          </div>
        </div>

        <div
          id="vulnerabilities-content"
          className="items-start w-full px-4 md:px-7 space-y-4"
        >
          {Array.isArray(CVEData.vulnerabilities) &&
          CVEData.vulnerabilities.length > 0 ? (
            CVEData.vulnerabilities.map((item) => (
              <div
                key={item.cve_id}
                className="flex flex-col md:flex-row w-full items-center space-y-2 md:space-y-0 md:space-x-4"
              >
                <CVEProduct data={item} />
              </div>
            ))
          ) : (
            <p className="px-2 md:px-5">No vulnerability data available.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default CVEDataController;
