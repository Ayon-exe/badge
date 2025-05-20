"use client";
import { useState, useEffect, useRef,} from "react";
import { useRouter } from "next/navigation"; 
import { BarChart, Bar, XAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { getTopCompanies, getProductsAndVendorsWatchlist } from "@/lib/fetch";
import  SkeletonBarCharts  from "@/components/Skeletonbar";

// **Extended Data Set**
const tempCompanies = [
  { name: "Apple", currentCVEs: 1025, avgMonthly: 24500, avgWeekly: 6100, changeLastMonth: -33.2, changeLastYear: +14.8, monthlyTrend: [75, 100, 50, 25, 100, 50, 75, 25, 50, 100, 75, 25] },
  { name: "auto location for wp job manager via google", currentCVEs: 1025, avgMonthly: 24500, avgWeekly: 6100, changeLastMonth: -33.2, changeLastYear: +14.8, monthlyTrend: [75, 100, 50, 25, 100, 50, 75, 25, 50, 100, 75, 25] },
  { name: "Google", currentCVEs: 970, avgMonthly: 23500, avgWeekly: 5900, changeLastMonth: -31.7, changeLastYear: -9.9, monthlyTrend: [50, 75, 100, 50, 25, 100, 75, 50, 100, 75, 25, 100] },
  { name: "Microsoft", currentCVEs: 900, avgMonthly: 22500, avgWeekly: 5600, changeLastMonth: -29.8, changeLastYear: -11.5, monthlyTrend: [100, 50, 75, 25, 100, 50, 75, 25, 50, 100, 25, 75] },
  { name: "Facebook", currentCVEs: 880, avgMonthly: 21500, avgWeekly: 5300, changeLastMonth: -27.5, changeLastYear: -8.9, monthlyTrend: [75, 100, 50, 25, 100, 75, 50, 100, 25, 75, 50, 100] },
  { name: "IBM", currentCVEs: 860, avgMonthly: 20800, avgWeekly: 5150, changeLastMonth: -26.0, changeLastYear: -7.7, monthlyTrend: [50, 25, 100, 75, 50, 100, 25, 75, 50, 100, 75, 25] },
  { name: "Cisco", currentCVEs: 810, avgMonthly: 19500, avgWeekly: 4900, changeLastMonth: -24.4, changeLastYear: -6.8, monthlyTrend: [100, 50, 25, 75, 100, 50, 25, 75, 100, 50, 25, 100] },
  { name: "Oracle", currentCVEs: 780, avgMonthly: 18500, avgWeekly: 4600, changeLastMonth: -22.8, changeLastYear: -5.9, monthlyTrend: [25, 75, 50, 100, 50, 75, 100, 50, 25, 100, 75, 50] },
  { name: "Adobe", currentCVEs: 760, avgMonthly: 18000, avgWeekly: 4500, changeLastMonth: -21.5, changeLastYear: -5.2, monthlyTrend: [75, 50, 100, 25, 100, 75, 50, 100, 25, 75, 50, 100] },
  { name: "Intel", currentCVEs: 740, avgMonthly: 17500, avgWeekly: 4400, changeLastMonth: -20.2, changeLastYear: -4.6, monthlyTrend: [100, 50, 75, 25, 100, 50, 75, 25, 50, 100, 25, 75] },
  { name: "Tesla", currentCVEs: 720, avgMonthly: 17000, avgWeekly: 4200, changeLastMonth: -18.9, changeLastYear: -4.1, monthlyTrend: [50, 25, 100, 75, 50, 100, 25, 75, 50, 100, 75, 25] }
];

const COLOR_PALETTES = [
  ["#FFB3C7", "#FF8AA8", "#FF5F85", "#C83857", "#B0304D", "#FFC2D1"],  // Soft Pink
  ["#FCA5A5", "#F87171", "#EF4444", "#C33434", "#B03030", "#FFBABA"],  // Soft Red
  ["#A6C8FF", "#6FA5FF", "#3D82FF", "#3E61C2", "#345BB0", "#B5D4FF"],  // Soft Blue
  ["#A5B4FC", "#818CF8", "#6366F1", "#3D46A0", "#353C8A", "#BDC7FA"],  // Soft Indigo
  ["#D2B3FF", "#B380FF", "#925EFF", "#6F45C2", "#613AB0", "#D8C2FF"],  // Soft Purple
  ["#81D4E3", "#5FB7CC", "#4498AD", "#297A88", "#266D7A", "#B0E0EA"],  // Muted Cyan
  ["#6FB7A5", "#5C9E8E", "#4A8577", "#286D5E", "#246256", "#A0D3C1"],  // Muted Teal
  ["#A7F3D0", "#6EE7B7", "#34D399", "#1F8A66", "#1F7D5C", "#BEEAC9"],  // Soft Green
  ["#BEF264", "#A3E635", "#84CC16", "#507010", "#46620E", "#D3F4A3"],  // Soft Lime
  ["#E5E7EB", "#D1D5DB", "#9CA3AF", "#656F83", "#5C6473", "#D6DAE0"]   // Soft Grey
];

// **Month Labels for Graph**
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export default function TopCompanies() {
  const [companies, setCompanies] = useState([]);
  const [productsAndVendors, setProductsAndVendors] = useState({ products: [], vendors: [] });
  const scrollRef = useRef(null);
  const isDragging = useRef(false);
  const startX = useRef(0);
  const scrollLeft = useRef(0);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await getTopCompanies();
        console.log(response);
        setCompanies(response.vendors);
        console.log("Fetched Top Companies Data:", companies);
      } catch (error) {
        console.error("Error fetching company data:", error);
      }
    };
    fetchData();
   }, []);




  // **Scroll Drag Functionality**
  const startDragging = (e) => {
    isDragging.current = true;
    startX.current = e.pageX - scrollRef.current.offsetLeft;
    scrollLeft.current = scrollRef.current.scrollLeft;
  };

  const stopDragging = () => {
    isDragging.current = false;
  };

  const handleMouseMove = (e) => {
    if (!isDragging.current) return;
    e.preventDefault();
    const x = e.pageX - scrollRef.current.offsetLeft;
    const walk = (x - startX.current) * 2;
    scrollRef.current.scrollLeft = scrollLeft.current - walk;
  };

  return (
    <div
      className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg p-6 w-full"
      style={{ minHeight: "400px" }} // Set a fixed minimum height for the container
    >
      <h2 className="text-lg font-semibold text-white">Yearly Timeline</h2>
      <p className="text-sm text-gray-400">A Month-wise view of all CVE's reported in the last 12 Months.</p>
  
      {companies?.length === 0 ? (
      // Skeleton loading state instead of simple "Loading..." text
      <SkeletonBarCharts />
    ) : (
        // Data display
        <div
          ref={scrollRef}
          className="mt-4 flex gap-4 overflow-x-auto scrollbar cursor-grab active:cursor-grabbing select-none"
          onMouseDown={startDragging}
          onMouseLeave={stopDragging}
          onMouseUp={stopDragging}
          onMouseMove={handleMouseMove}
        >
          {companies?.map((company, index) => (
            <CompanyCard key={index} company={company} colors={COLOR_PALETTES[index % COLOR_PALETTES.length]} />
          ))}
        </div>
      )}
    </div>
  );
}

  // **Truncating Function**
  const truncateString = (str, maxLength) => {
    if (str.length <= maxLength) {
      return str;
    }
    return str.substring(0, maxLength) + '...';
  };

// **Company Card Component**

const CompanyCard = ({ company, colors, type }) => {
  const [selectedMonth, setSelectedMonth] = useState(null);
  const [companyType, setCompanyType] = useState(type); 
  const router = useRouter(); 

  
  useEffect(() => {
    const fetchWatchlistData = async () => {
     
      if (!company || !company.name) return;
      
      try {
        const data = await getProductsAndVendorsWatchlist();
        
        // Make sure data has the expected structure
        if (data && data.vendors && data.products) {
          // Check if the company exists in vendors list
          const isVendor = data.vendors.some(vendor => 
            vendor.vendor && 
            vendor.vendor.toLowerCase() === company.name.toLowerCase()
          );
          
          // Check if the company exists in products list
          const isProduct = data.products.some(product => 
            product.product && 
            product.product.toLowerCase() === company.name.toLowerCase()
          );
          
          
          if (isVendor) {
            setCompanyType("vendor");
          } else if (isProduct) {
            setCompanyType("product");
          }
          
        }
      } catch (error) {
        console.error("Error fetching watchlist data:", error);
      }
    };
    
    fetchWatchlistData();
  }, [company?.name]);

  const barData = company.monthlyDistribution.map((value, index) => ({
    name: value.name,
    count: value.count,
  }));

  const handleCardClick = () => {
    
    if (!company || !company.name) {
      console.error("Invalid company object:", company);
      return;
    }
  
   
    if (companyType === "vendor") {
      router.push(`/vendor/${encodeURIComponent(company.name)}`);
    } else if (companyType === "product") {
      router.push(`/product/${encodeURIComponent(company.name)}`);
    } else {
      console.error("Unknown type for company:", company);
    }
  };

  return (
    <div
      className="w-72 p-2 rounded-lg text-white shrink-0 space-y-2 cursor-pointer border border-transparent hover:border-cyan-500 transition-all duration-200"
      onClick={handleCardClick} 
    >
      {/* **Company Name (No Background)** */}
      <h3 className="text-lg font-bold">
        {truncateString(
          `${company.name.charAt(0).toUpperCase()}${company.name.slice(1)}`,
          25
        )}
      </h3>
      {/* **Main Card for Current CVEs & Bar Chart** */}
      <div
        className="px-2 py-1 rounded-xl"
        style={{ backgroundColor: colors[0] }}
      >
        <p
          className="font-montserrat text-xl font-medium"
          style={{ color: colors[3] }}
        >
          Current CVEs
        </p>
        <p
          className="font-montserrat text-3xl font-black"
          style={{ color: colors[4] }}
        >
          {company.currentCVEs.toLocaleString("en-GB")}
        </p>

        {/* **Bar Chart (Monthly CVEs) ** */}
        <div className="mt-2 py-2 w-full">
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={barData}>
              <XAxis
                dataKey="name"
                stroke="none"
                tick={{ fontSize: 12, fill: "black" }}
                interval={1}
              />
              {/* <Tooltip
                cursor={<div style={{ fill: "rgba(255, 255, 255, 0.2)" }} />}
                contentStyle={{
                  backgroundColor: "rgba(255, 255, 255, 0.3)",
                  backdropFilter: "blur(10px)",
                  WebkitBackdropFilter: "blur(10px)",
                  borderRadius: 4,
                  padding: 8,
                  boxShadow: "0 0 10px rgba(0, 0, 0, 0.4)",
                  color: "rgba(0, 0, 0, 0.8)",
                }}
                wrapperStyle={{
                  backgroundColor: "rgba(255, 255, 255, 0.2)",
                  borderRadius: 4,
                }}
              /> */}
              <Bar
                dataKey="count"
                fill={colors[4]}
                radius={[10, 10, 10, 10]}
                barSize={10}
                isAnimationActive={true}
                onClick={(data, index) => setSelectedMonth(index)}
                background={{
                  fill: "rgba(0,0,0,0.2)",
                  radius: [10, 10, 10, 10],
                }}
              >
                {barData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={
                      selectedMonth === null || selectedMonth === index
                        ? colors[4]
                        : "rgba(0,0,0,0.2)"
                    }
                  />
                  
                  
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* **Second Row - Avg Monthly & Avg Weekly CVEs** */}
      <div className="grid grid-cols-2 gap-1">
        {[
          { label: "Avg Monthly CVEs", value: company.avgMonthlyCV },
          { label: "Avg Weekly CVEs", value: company.avgWeeklyCV },
        ].map((stat, idx) => (
          <div
            key={idx}
            className="p-1 rounded-xl text-center"
            style={{ backgroundColor: colors[1] }}
          >
            <p
              className="text-sm font-montserrat text-black font-semibold"
              style={{ color: colors[4] }}
            >
              {stat.label}
            </p>
            <p
              className="text-xl font-montserrat text-black font-bold"
              style={{ color: colors[4] }}
            >
              {stat.value.toLocaleString("en-GB")}
            </p>
          </div>
        ))}
      </div>

      {/*  **Third Row - Change from Last Month & Last Year** */}
      <div className="grid grid-cols-2 gap-1">
        {[
          { label: "% Change from Last Month", value: parseInt(company.changeLastMonth) },
          { label: "% Change from Last Year", value: parseInt(company.changeLastYear) },
        ].map((stat, idx) => (
          <div
            key={idx}
            className="p-1 rounded-xl text-center"
            style={{ backgroundColor: colors[2] }}
          >
            <p
              className="text-sm font-montserrat text-black font-semibold"
              style={{ color: "white" }}
            >
              {stat.label}
            </p>
            <p
              className="text-xl font-montserrat font-bold"
              style={{ color: "white" }}
            >
              <span
                style={{
                  color: stat.value < 0 ? "red" : "green",
                  fontSize: "18px",
                }}
              >
                {stat.value < 0 ? <>&#x2193;</> : <>&#x2191;</>}
              </span>
              {Math.abs(stat.value).toFixed(1)}%
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};