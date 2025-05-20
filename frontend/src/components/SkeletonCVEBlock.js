import React from "react";

const SkeletonCVEBlock = () => {
  return (
    <div className="w-full flex flex-col md:flex-row divide-x divide-gray-600 bg-slate-950/75 backdrop-blur-md rounded-lg border-2 border-gray-600 border-opacity-50 p-6 md:p-7 justify-between my-4 gap-4 animate-pulse">
      {/* Placeholder for CVE ID */}
      <div className="flex flex-col w-full">
        <div className="h-8 bg-gray-500 dark:bg-gray-500 rounded-md w-1/3 mb-2"></div> {/* CVE ID placeholder */}
        <div className="h-4 bg-gray-400 dark:bg-gray-400 rounded-md w-full"></div> {/* Description placeholder */}
        <div className="h-4 bg-gray-400 dark:bg-gray-400 rounded-md w-5/6 mt-2"></div> {/* Description placeholder */}
      </div>

      {/* Placeholder for CVSS and EPSS Score */}
      <div className="flex flex-col justify-between pl-4 w-full md:w-1/4 space-y-2 mt-4 md:mt-0">
        {/* CVSS Score placeholder */}
        <div className="flex justify-between items-center">
          <span className="h-4 bg-gray-400 dark:bg-gray-400 w-16 rounded-sm"></span>
          <div className="h-8 bg-gray-500 dark:bg-gray-500 rounded-md w-16"></div>
        </div>

        {/* EPSS Score placeholder */}
        <div className="flex justify-between items-center">
          <span className="h-4 bg-gray-400 dark:bg-gray-400 w-16 rounded-sm"></span>
          <div className="h-8 bg-gray-500 dark:bg-gray-500 rounded-md w-16"></div>
        </div>

        {/* Published date placeholder */}
        <div className="flex justify-between items-center">
          <span className="h-4 bg-gray-400 dark:bg-gray-400 w-16 rounded-sm"></span>
          <div className="h-6 bg-gray-500 dark:bg-gray-500 rounded-md w-20"></div>
        </div>

        {/* Updated date placeholder */}
        <div className="flex justify-between items-center">
          <span className="h-4 bg-gray-400 dark:bg-gray-400 w-16 rounded-sm"></span>
          <div className="h-6 bg-gray-500 dark:bg-gray-500 rounded-md w-20"></div>
        </div>
      </div>
    </div>
  );
};

const CVESkeletonPage = () => {
  const skeletonArray = new Array(5).fill(null); // Number of skeletons to display (adjust as needed)

  return (
    <div className="min-h-screen w-full flex justify-center items-center">
      <div className="text-white justify-start bg-slate-950/30 flex flex-col mb-4 pt-4 mx-10 overflow-x-hidden backdrop-blur-md shadow-lg rounded-lg min-h-screen w-full md:w-4/5">
        <div className="items-start px-7 md:px-10 shadow-lg bg-slate-950/30 py-7 md:py-10">
          {/* Filter and Sorting Controls */}
          <div className="flex flex-col md:flex-row content-center space-x-4 my-4">
            <p className="place-content-center">Published in:</p>
            <div className="h-8 bg-gray-500 dark:bg-gray-500 rounded-md w-32 mb-2"></div> {/* Date selector skeleton */}
          </div>
          <div className="flex flex-col md:flex-row space-x-4 my-4">
            <div className="h-8 bg-gray-500 dark:bg-gray-500 rounded-md w-32 mb-2"></div> {/* Filter skeleton */}
            <div className="h-8 bg-gray-500 dark:bg-gray-500 rounded-md w-32 mb-2"></div> {/* Sort by skeleton */}
            <div className="h-8 bg-gray-500 dark:bg-gray-500 rounded-md w-32 mb-2"></div> {/* Order by skeleton */}
          </div>
        </div>

        <div className="items-start w-full">
          {/* Generate Skeletons */}
          {skeletonArray.map((_, index) => (
            <SkeletonCVEBlock key={index} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default CVESkeletonPage;
