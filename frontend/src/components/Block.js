import React from "react";

export default function Block({
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
}) {
  return (
    <div className="w-full">
      {/* Responsive Grid: 2 columns on mobile, 5 columns on sm and above */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 w-full">
        {/* Block 1 */}
        <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg h-auto w-full justify-center flex flex-col">
          <p className="text-[#00CBF0] text-lg font-semibold pt-2 px-4">
            {title1}
          </p>
          <p className="text-md md:text-2xl font-semibold px-4 pb-2">{desc1}</p>
          <p className="text-sm md:text-sm font-semibold px-4 pb-2">{info1}</p>
        </div>
        {/* Block 2 */}
        <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg h-auto w-full justify-center flex flex-col">
          <p className="text-[#00CBF0] text-lg font-semibold pt-2 px-4">
            {title2}
          </p>
          <p className="text-md md:text-2xl font-semibold px-4 pb-2">{desc2}</p>
          <p className="text-sm md:text-sm font-semibold px-4 pb-2">{info2}</p>
        </div>
        {/* Block 3 */}
        <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg h-auto w-full justify-center flex flex-col">
          <p className="text-[#00CBF0] text-lg font-semibold pt-2 px-4">
            {title3}
          </p>
          <p className="text-md md:text-2xl font-semibold px-4 pb-2">{desc3}</p>
          <p className="text-sm md:text-sm font-semibold px-4 pb-2">{info3}</p>
        </div>
        {/* Block 4 */}
        <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg h-auto w-full justify-center flex flex-col">
          <p className="text-[#00CBF0] text-lg font-semibold pt-2 px-4">
            {title4}
          </p>
          <p className="text-md md:text-2xl font-semibold px-4 pb-2">{desc4}</p>
          <p className="text-sm md:text-sm font-semibold px-4 pb-2">{info4}</p>
        </div>
        {/* Block 5: Span full width on mobile (2 columns), normal on sm and above */}
        <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg h-auto w-full justify-center flex flex-col col-span-2 sm:col-span-1">
          <p className="text-[#00CBF0] text-lg font-semibold pt-2 px-4">
            {title5}
          </p>
          <p className="text-md md:text-2xl font-semibold px-4 pb-2">{desc5}</p>
          <p className="text-sm md:text-sm font-semibold px-4 pb-2">{info5}</p>
        </div>
      </div>
    </div>
  );
}
