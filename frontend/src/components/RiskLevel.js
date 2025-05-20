"use client";
import { useState, useEffect } from "react";
import { Clock } from "lucide-react"; // Import clock icon
import { getRiskLevelOverview, getTotalFixableCves } from "@/lib/fetch";

export default function RiskLevel() {
  // Placeholder dynamic data (Replace with API data)
  const [riskData, setRiskData] = useState({
    totalFixable: 0,
    percentageFixable: 0, // Adjust this value to see different colors
    avgDaysSinceFix: 0, // Example dynamic days count
    totalFixableCves: 0, // Add this field
    fixablePercentage: 0 // Add this field
  });

  useEffect(() => {
    const fetchRiskData = async () => {
      try {
        // Fetch data for fixable CVEs, percentage, and average days since fix
        const riskLevelData = await getRiskLevelOverview();
        // Fetch data for total fixable CVEs
        const totalFixableCvesData = await getTotalFixableCves();

        setRiskData({
            totalFixable: riskLevelData.fixableCVEs, 
            percentageFixable: parseInt(riskLevelData.fixablePercentage), 
            avgDaysSinceFix: totalFixableCvesData.avgFixDays,
            totalFixableCves: totalFixableCvesData.totalFixableCves, // Set this field
            fixablePercentage: Math.round(totalFixableCvesData.fixablePercentage) // Set this field
        });

        console.log("Fetched Risk Level Data:", riskData);
      } catch (error) {
        console.error("Error fetching Risk Level data:", error);
      }
    };

    fetchRiskData();
  }, []);

  // Determine Risk Level based on % of Total Fixable CVEs
  const getRiskStatus = (percentage) => {
    if (percentage <= 10) return { label: "Very Good", color: "bg-green-700", bgColor: "bg-green-900/40", glow: "shadow-green-400/40" };
    if (percentage <= 25) return { label: "Good", color: "bg-green-500", bgColor: "bg-green-700/30", glow: "shadow-green-300/30" };
    if (percentage <= 40) return { label: "Pay Attention", color: "bg-yellow-500", bgColor: "bg-yellow-700/30", glow: "shadow-yellow-300/30" };
    if (percentage <= 60) return { label: "Urgent", color: "bg-orange-500", bgColor: "bg-orange-700/30", glow: "shadow-orange-300/30" };
    return { label: "Critical", color: "bg-red-500", bgColor: "bg-red-700/30", glow: "shadow-red-400/30" };
  };

  const riskStatus = getRiskStatus(riskData.fixablePercentage);

  return (
    <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg p-4 w-full pb-2">
      {/* 🏷 Header */}
      <h2 className="text-lg font-semibold text-white mb-2">Risk Level Overview</h2>

      {/* 📊 Column Labels */}
      <div className="grid grid-cols-4 text-sm text-gray-400 px-3 py-1 border-b border-gray-700">
        <span>Risk Level</span>
        <span className="text-center">Total Fixable CVEs</span>
        <span className="text-center">% of Total Fixable CVEs</span>
        <span className="text-right">Average CVE lifetime</span>
      </div>

      {/* 🟡 Inner Container with Colored Background */}
      <div className={`grid grid-cols-4 items-center p-2 rounded-lg mt-2 ${riskStatus.bgColor} ${riskStatus.glow} transition-all duration-500`}>
        
        {/* 🟠 Risk Level with Glow Effect */}
<div className={`flex justify-center sm:justify-start items-center gap-2 font-semibold text-white px-3 py-2 rounded-lg shadow-md ${riskStatus.color} transition-all duration-300`}>
  <div className="w-3 h-3 rounded-full bg-white"></div> {/* Status Indicator */}
  <span>{riskStatus.label} {riskData.fixablePercentage}%</span>
</div>

        {/* 📌 Total Fixable CVEs - Large, Bolder Text */}
<div className="text-center text-white text-xl sm:text-2xl font-bold tracking-wide">
  {riskData.totalFixableCves} CVEs
</div>

        {/* 📈 Progress Bar with Animation */}
        <div className="relative flex items-center">
          <div className="w-full h-5 bg-gray-800 rounded-full overflow-hidden">
            <div
              className={`h-full ${riskStatus.color} transition-all duration-700 ease-in-out`}
              style={{ width: `${riskData.fixablePercentage}%` }}
            ></div>
          </div>
        </div>

        {/* ⏳ Avg. Days Since Fix - Faded Clock Icon */}
        <div className="flex items-center justify-end gap-2 text-gray-300">
          <Clock className="text-gray-400 w-5 h-5" />{/* Clock Icon */}
          <span className="text-lg">{riskData.avgDaysSinceFix} Days</span>
        </div>
      </div>
    </div>
  );
}
