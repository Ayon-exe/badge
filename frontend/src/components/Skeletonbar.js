import React, { useRef } from "react";

const SkeletonBarCharts = () => {
  // Create 5 skeleton charts with similar configurations
  const skeletonCharts = [
    { barCount: 12 },
    { barCount: 12 },
    { barCount: 12 },
    { barCount: 12 },
    { barCount: 12 }
  ];

  const scrollRef = useRef(null);

  return (
    <div
      ref={scrollRef}
      className="mt-4 flex gap-8 overflow-x-auto scrollbar cursor-grab active:cursor-grabbing select-none"
    >
      {skeletonCharts.map((chart, chartIndex) => {
        return (
          <div
            key={chartIndex}
            className="bg-gray-200/20 dark:bg-gray-700/20 p-4 flex flex-col border border-gray-300/10 min-w-[280px] rounded-lg"
            role="status"
          >
            {/* Chart title and skeleton value */}
            <div className="mb-3">
              <div className="h-5 w-32 bg-gray-200/30 dark:bg-gray-700/30 rounded mb-2 animate-pulse"></div>
              <div className="h-8 w-24 bg-gray-200/30 dark:bg-gray-700/30 rounded animate-pulse"></div>
            </div>
            
            {/* Bar chart skeleton */}
            <div className="flex items-end h-32 space-x-2 mb-4">
              {Array(chart.barCount).fill(0).map((_, i) => {
                // Generate random heights for bars to create visual variety
                const height = Math.floor(Math.random() * 60) + 20;
                
                return (
                  <div
                    key={i}
                    className="w-3 rounded-full bg-gray-200/30 dark:bg-gray-700/30 animate-pulse"
                    style={{ height: `${height}%` }}
                  ></div>
                );
              })}
            </div>
            
            {/* X-axis labels */}
            <div className="flex justify-between text-xs mt-1">
              <div className="h-2.5 w-8 bg-gray-200/30 dark:bg-gray-700/30 rounded animate-pulse"></div>
              <div className="h-2.5 w-8 bg-gray-200/30 dark:bg-gray-700/30 rounded animate-pulse ml-auto"></div>
            </div>
            
            {/* Bottom cards */}
            <div className="grid grid-cols-2 gap-2 mt-4">
              {/* Monthly averages */}
              <div className="rounded p-2">
                <div className="h-3 w-24 bg-gray-200/30 dark:bg-gray-700/30 rounded mb-2 animate-pulse"></div>
                <div className="h-5 w-24 bg-gray-200/30 dark:bg-gray-700/30 rounded animate-pulse"></div>
              </div>
              
              {/* Weekly averages */}
              <div className="rounded p-2">
                <div className="h-3 w-24 bg-gray-200/30 dark:bg-gray-700/30 rounded mb-2 animate-pulse"></div>
                <div className="h-5 w-16 bg-gray-200/30 dark:bg-gray-700/30 rounded animate-pulse"></div>
              </div>
              
              {/* % Change from last month */}
              <div className="rounded p-2">
                <div className="h-3 w-24 bg-gray-200/30 dark:bg-gray-700/30 rounded mb-2 animate-pulse"></div>
                <div className="h-5 w-16 bg-gray-200/30 dark:bg-gray-700/30 rounded animate-pulse"></div>
              </div>
              
              {/* % Change from last year */}
              <div className="rounded p-2">
                <div className="h-3 w-24 bg-gray-200/30 dark:bg-gray-700/30 rounded mb-2 animate-pulse"></div>
                <div className="h-5 w-16 bg-gray-200/30 dark:bg-gray-700/30 rounded animate-pulse"></div>
              </div>
            </div>
            <span className="sr-only">Loading...</span>
          </div>
        );
      })}
    </div>
  );
}

export default SkeletonBarCharts;