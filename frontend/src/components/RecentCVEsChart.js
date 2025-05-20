import { useState, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip } from "recharts";
import { getRecentCVEsUpdate } from "@/lib/fetch";
import  SkeletonBarGraph  from "@/components/Skeletonchart";

// Custom Tooltip component
function CustomTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div className="bg-white/10 backdrop-blur-sm rounded p-2 text-white border border-white/20">
        <p className="font-semibold">{label}</p>
        <p>{`CVEs: ${payload[0].value}`}</p>
      </div>
    );
  }
  return null;
}

export default function RecentCVEsChart() {
  const [selectedPeriod, setSelectedPeriod] = useState("monthly");
  const [chartData, setChartData] = useState([]);
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  // *Temporary Static Data (Will Be Replaced by API)*
   const dailyData = [
    { name: "Mon", CVEs: 10 },
    { name: "Tue", CVEs: 15 },
    { name: "Wed", CVEs: 20 },
    { name: "Thu", CVEs: 30 },
    { name: "Fri", CVEs: 18 },
    { name: "Sat", CVEs: 22 },
    { name: "Sun", CVEs: 25 },
  ];

  const weeklyData = [
    { name: "Week 1", CVEs: 50 },
    { name: "Week 2", CVEs: 80 },
    { name: "Week 3", CVEs: 65 },
    { name: "Week 4", CVEs: 90 },
  ];

  const monthlyData = [
    { name: "Jan", CVEs: 250 },
    { name: "Feb", CVEs: 180 },
    { name: "Mar", CVEs: 200 },
    { name: "Apr", CVEs: 240 },
    { name: "May", CVEs: 300 },
    { name: "Jun", CVEs: 280 },
    { name: "Jul", CVEs: 310 },
    { name: "Aug", CVEs: 270 },
    { name: "Sep", CVEs: 290 },
    { name: "Oct", CVEs: 320 },
    { name: "Nov", CVEs: 310 },
    { name: "Dec", CVEs: 330 },
  ];

  // *Fetch Data from API (To Be Implemented)*
  const fetchData = async (period) => {
    setIsLoading(true);
    setError(null);

    try {
      let response;
      let jsonData;

      // *TODO: Replace with actual API endpoints*
      if (period === "daily") {
        response = await getRecentCVEsUpdate("daily");
        jsonData = response.graphData; // Placeholder Data
      } else if (period === "weekly") {
        response = await getRecentCVEsUpdate("weekly");
        jsonData = response.graphData; // Placeholder Data
      } else if (period === "monthly") {
        response = await getRecentCVEsUpdate("monthly");
        jsonData = response.graphData; // Placeholder Data
      }
      
      // For now, you can test with static data if needed:
      // jsonData = period === "daily" ? dailyData : period === "weekly" ? weeklyData : monthlyData;

      setChartData(jsonData);
    } catch (error) {
      setError("Error fetching data");
      console.error("Error fetching Recent CVEs data:", error);
    } finally {
      setIsLoading(false);
    }
  };

  // *Initial Data Load*
  useEffect(() => {
    fetchData(selectedPeriod);
  }, [selectedPeriod]);

  return (
    <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg p-4">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold text-white">Recent CVEs and Updates</h2>
        {/* Dropdown Menu */}
        <select
          value={selectedPeriod}
          onChange={(e) => setSelectedPeriod(e.target.value)}
          className="bg-slate-800 text-white border border-white/20 px-2 py-1 rounded-md focus:outline-none"
        >
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
      </div>

      {chartData.length === 0 ? (
        <p className="text-sm text-gray-300 mb-2">Please add something to your watchlist.</p>
      ) : (
        <p className="text-sm text-[#00CBF0]">Displaying {selectedPeriod} data</p>
      )}

      {isLoading ? (
        <SkeletonBarGraph />
      ) : (
        <div className="mt-2">
          <ResponsiveContainer width="100%" height={315} maxHeight={450}>
            <BarChart data={chartData} margin={{ left: -25, right: 0, top: 0, bottom: 0 }}>
              <XAxis dataKey="name" stroke="white" />
              <YAxis stroke="white" />
              <Tooltip
                cursor={{ fill: "rgba(255, 255, 255, 0.1)" }}
                content={<CustomTooltip />}
              />
              <Bar dataKey="CVEs" onMouseLeave={() => setHoveredIndex(null)}>
                {chartData.map((entry, index) => (
                  <Cell
                   key={`cell-${index}`}
                    fill={
                      hoveredIndex === null
                        ? "#00A3FF"
                        : hoveredIndex === index
                        ? "#00A3FF"
                        : "rgba(255, 255, 255, 0.3)"
                    }
                    stroke={hoveredIndex === index ? "#00A3FF" : "none"}
                    strokeWidth={hoveredIndex === index ? 2 : 0}
                    onMouseEnter={() => setHoveredIndex(index)}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}