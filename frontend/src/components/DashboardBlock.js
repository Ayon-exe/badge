import React from "react";
import { ArrowRight } from "lucide-react";
export default function DashboardBlock({
  title1,
  desc1,
  info1,
  title2,
  desc2,
  info2,
  title3,
  desc3,
  info3,
  title4,
  desc4,
  info4,
  title5,
  desc5,
  info5,
  onClickVendor,
  onClickProduct,
  onClickResolved,
  onClickOpen,
  onClickIgnored,
  className = "",
}) {
  // Common card style for reuse
  const cardClass = "bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg flex flex-col justify-center transition-all duration-300 hover:border-cyan-400 hover:shadow-cyan-400/20 cursor-pointer";
  
  return (
    <div
      className={`w-full border border-cyan-400 rounded-md sm:border-transparent ${className}`}
    >
      {/* Grid container that responsively adjusts based on screen size */}
      <div className="grid grid-cols-2 gap-2 md:grid-cols-3 lg:grid-cols-5 xl:grid-cols-5">
        <div
          onClick={onClickVendor}
          className={`${cardClass} p-2 min-h-24 md:min-h-32`}
        >
          <p className="text-[#00CBF0] text-xs sm:text-sm font-semibold text-center">
            {title1}
          </p>
          <p className="text-lg sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-center my-1">
            {desc1}
          </p>
          <p className="text-xs font-semibold text-center">
            {info1}
          </p>
        </div>
        
        <div
          onClick={onClickProduct}
          className={`${cardClass} p-2 min-h-24 md:min-h-32`}
        >
          <p className="text-[#00CBF0] text-xs sm:text-sm font-semibold text-center">
            {title2}
          </p>
          <p className="text-lg sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-center my-1">
            {desc2}
          </p>
          <p className="text-xs font-semibold text-center">
            {info2}
          </p>
        </div>
        
        <div
          onClick={onClickResolved}
          className={`${cardClass} p-2 min-h-24 md:min-h-32 relative`}
        >
          <div className="absolute bottom-2 right-2 text-white">
            <ArrowRight size={16} />
          </div>
          <p className="text-[#00CBF0] text-xs sm:text-sm font-semibold text-center">
            {title3}
          </p>
          <p className="text-lg sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-center my-1">
            {desc3}
          </p>
          <p className="text-xs font-semibold text-center">
            {info3}
          </p>
        </div>
        
        <div
          onClick={onClickOpen}
          className={`${cardClass} p-2 min-h-24 md:min-h-32 relative`}
        >
          <div className="absolute bottom-2 right-2 text-white">
            <ArrowRight size={16} />
          </div>
          <p className="text-[#00CBF0] text-xs sm:text-sm font-semibold text-center">
            {title4}
          </p>
          <p className="text-lg sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-center my-1">
            {desc4}
          </p>
          <p className="text-xs font-semibold text-center">
            {info4}
          </p>
        </div>
        
        <div
          onClick={onClickIgnored}
          className={`${cardClass} p-2 min-h-24 md:min-h-32 relative col-span-2 md:col-span-1`}
        >
          <div className="absolute bottom-2 right-2 text-white">
            <ArrowRight size={16} />
          </div>
          <p className="text-[#00CBF0] text-xs sm:text-sm font-semibold text-center">
            {title5}
          </p>
          <p className="text-lg sm:text-2xl md:text-3xl lg:text-4xl font-semibold text-center my-1">
            {desc5}
          </p>
          <p className="text-xs font-semibold text-center">
            {info5}
          </p>
        </div>
      </div>
    </div>
  );
}