import React from "react";
import SkeletonCVEBlock from "./SkeletonCVEBlock"; // Import the skeleton block

const CVESkeletonPage = () => {
  const skeletonArray = new Array(5).fill(null); // Number of skeletons to display (adjust as needed)

  return (
    <div className="min-h-screen w-full flex justify-center items-center">
      <div className="text-white justify-start bg-slate-950/30 flex flex-col mb-4 pt-4 mx-10 overflow-x-hidden backdrop-blur-md shadow-lg rounded-lg min-h-screen w-full md:w-4/5">
        <div className="items-start px-7 shadow-lg bg-slate-950/30 py-7 ">
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
          {skeletonArray.map((_, index) => (
            <SkeletonCVEBlock key={index} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default CVESkeletonPage;
