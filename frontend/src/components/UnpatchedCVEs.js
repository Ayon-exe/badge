"use client";
import { useState, useEffect } from "react";
import { getUnpatchedFixableCVEs } from "@/lib/fetch";

export default function UnpatchedCVEs() {
  // Placeholder data (Replace with API later)
  const [data, setData] = useState({
    percentageFixable: 57,
    high: 1,  // High-severity CVEs
    medium: 1, 
    low: 1, 
    total: 3, 
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Example API call (Replace with actual API)
        const jsonData = await getUnpatchedFixableCVEs();

        const result = { 
          high: jsonData.high,
          low: jsonData.low,
          medium: jsonData.medium,
          total: jsonData.medium + jsonData.high + jsonData.low, 
          percentageFixable: jsonData.percentageFixable
        };
        console.log(result);
        setData(result);
      } catch (error) {
        console.error("Error fetching Unpatched CVEs data:", error);
      }
    };

    fetchData();
  }, []);

  return (
    <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg p-4 h-full">
      {/* Header Section */}
      <h2 className="text-lg font-semibold text-white">Unpatched Fixable CVEs</h2>
      {data.total === 0 ? (
        <p className="text-sm text-gray-300 mb-4">Please add something to your watchlist.</p>
      ) : (
        <p className="text-sm text-[#00CBF0]">{data.percentageFixable}% of CVEs with patches available</p>
      )}
      
      {/* Pixel Bars Section */}
      {data.total > 0 && (
        <div className="mt-5 space-y-4">
          <PixelBar label="High" count={data.high} color="bg-red-500" allData={data} />
          <PixelBar label="Medium" count={data.medium} color="bg-yellow-500" allData={data} />
          <PixelBar label="Low" count={data.low} color="bg-green-500" allData={data} />
          <PixelBar label="Total" count={data.total} color="bg-gray-500" allData={data} />
        </div>
      )}
    </div>
  );
  }
  
  // **Pixel-Based Progress Bar Component with Auto-Scaling and Hover Tooltip**
  const PixelBar = ({ label, count, color, allData }) => {
    const totalSegments = 10; // Number of pixel "blocks" in the bar
    const fillRatio = count / allData.total; // Percentage fill for this severity
    const filledBlocks = Math.round(fillRatio * totalSegments); // Number of fully filled blocks
    const emptyBlocks = totalSegments - filledBlocks; // Number of empty blocks
    
    // Calculate the percentage for this severity category
    const percentage = ((count / allData.total) * 100).toFixed(2);
    
    return (
      <div className="group relative">
        {/* Label & Count */}
        <div className="flex text-sm text-gray-300 mb-2 justify-between">
          <span>{label}</span>
          <span className="relative">
            {count}
          </span> {/* Moved count slightly to the left */}
        </div>
        
        {/* Pixel Bar Grid */}
        <div className="flex space-x-1">
          {/* Filled Blocks */}
          {[...Array(Math.max(0, filledBlocks || 0))].map((_, index) => (
            <div 
              key={`filled-${index}`}
              className={`w-5 h-9 border-2 border-gray-900 rounded-sm ${color} transition-all duration-700`}
            ></div>
          ))}
          
          {/* Empty Blocks */}
          {[...Array(Math.max(0, emptyBlocks || 0))].map((_, index) => (
            <div 
              key={`empty-${index}`}
              className="w-5 h-9 border-2 border-gray-900 rounded-sm bg-gray-800 transition-all duration-700"
            ></div>
          ))}
        </div>
        
        {/* Hover Tooltip */}
        <span className="absolute left-1/2 transform -translate-x-1/2 -top-2 opacity-0 group-hover:opacity-100 transition bg-white/10 backdrop-blur-sm text-white text-xs rounded px-2 py-1 border border-white/20">
          {percentage}% fixable in {label}
        </span>
      </div>
    );
  };