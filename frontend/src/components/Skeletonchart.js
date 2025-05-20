import React from "react";

const SkeletonBarChart = () => {
  // Hardcoded bar heights in pixels for consistency
  const barHeights = [60, 200, 80, 220, 180, 140, 40, 60, 30, 10, 20, 20];
  
  return (
    <div
      role="status"
      className="w-full h-[315px] max-h-[450px] bg-gray-900 dark:bg-gray-900 animate-pulse p-4 relative"
    >
      {/* Chart area with bars */}
      <div className="flex items-end h-[300px] w-full space-x-1 pr-4 pl-6">
        {barHeights.map((height, index) => (
          <div
            key={index}
            className="flex-1 flex flex-col justify-end items-center"
          >
            {/* Bar with increased opacity and reduced width - make width responsive */}
            <div
              className="w-full max-w-7 bg-gray-400 dark:bg-gray-400 rounded-sm"
              style={{ 
                height: `${height}px`,
                minWidth: '4px' // Minimum width for mobile
              }}
            ></div>
            
            {/* X-axis label (month) - showing for all bars */}
            <div className="h-4 bg-gray-500 dark:bg-gray-500 w-full max-w-7 mt-2 mx-auto rounded-sm"></div>
          </div>
        ))}
      </div>
      
      {/* Y-axis labels (left side) */}
      <div className="absolute left-4 top-6 bottom-10 flex flex-col justify-between">
        <div className="h-3 bg-gray-400 dark:bg-gray-400 w-6 rounded-sm"></div>
        <div className="h-3 bg-gray-400 dark:bg-gray-400 w-8 rounded-sm"></div>
        <div className="h-3 bg-gray-400 dark:bg-gray-400 w-6 rounded-sm"></div>
        <div className="h-3 bg-gray-400 dark:bg-gray-400 w-8 rounded-sm"></div>
      </div>
      
      <span className="sr-only">Loading...</span>
    </div>
  );
};

export default SkeletonBarChart;