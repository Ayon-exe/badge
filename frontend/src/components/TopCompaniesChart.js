import { useState, useEffect } from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { getTopCompaniesRadial } from "@/lib/fetch";

const COLORS = [
  "#FF5F85", // Deep Crimson  
  "#EF4444", // Rich Teal Blue  
  "#3D82FF", // Deep Emerald  
  "#6366F1", // Burnt Orange  
  "#925EFF", // Royal Purple  
  "#4498AD", // Deep Gold  
  "#4A8577", // Dark Magenta  
  "#34D399", // Midnight Steel Blue  
  "#84CC16", // Dark Forest Green  
  "#9CA3AF", // Warm Bronze  
];

// Custom Tooltip with glass effect
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

export default function TopCompaniesChart() {
  const [companies, setCompanies] = useState([
    { name: "", CVEs: 100 },
  ]);
  const [vendors, setVendors] = useState([]);
  const [products, setProducts] = useState([]);

  useEffect(() => {
    const fetchCompanyData = async () => {
      try {
        const response = await getTopCompaniesRadial();
        const vendorsWithCapitalizedNames = response.vendors.map((vendor) => ({
          ...vendor,
          name: vendor.name.charAt(0).toUpperCase() + vendor.name.slice(1),
        }));
        const productsWithCapitalizedNames = response.products.map((product) => ({
          ...product,
          name: product.name.charAt(0).toUpperCase() + product.name.slice(1),
        }));
        setVendors(vendorsWithCapitalizedNames);
        setProducts(productsWithCapitalizedNames);
        console.log("Fetched Vendors Data:", vendors);
        console.log("Fetched Products Data:", products);
      } catch (error) {
        console.error("Error fetching company data:", error);
      }
    };

    fetchCompanyData();
  }, []);

  return (
    <div className="card w-full">
      <div className="content w-full relative transition-transform duration-1000">
        <div className="front absolute w-full">
          <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg p-4 h-full">
            {/* Flip Icon - Undo Icon */}
            <div className="absolute top-2 right-2 cursor-pointer">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="30"
                height="30"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="svg-flip-icon transform transition duration-300 rotate-0 hover:rotate-180"
              >
                <path d="M3 7v6h6" />
                <path d="M21 17a9 9 0 0 0-9-9 9 9 0 0 0-6 2.3L3 13" />
              </svg>
            </div>


            <h2 className="text-lg font-semibold text-white mb-4">Top Vendors with Highest CVEs</h2>
            {vendors.length === 0 ? (
              <p className="text-sm text-gray-300 mb-4">Please add something to your watchlist.</p>
            ) : (
              <p className="text-sm text-[#00CBF0]">Displaying top vendors with highest CVEs</p>
            )}

            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={vendors}
                  dataKey="CVEs"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  innerRadius={60}
                  offsetRadius={10}
                  stroke="#000000"
                  label={(entry) => entry.name}
                >
                  {vendors.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="back absolute w-full">
          <div className="bg-slate-950/75 backdrop-blur-sm border border-white/20 rounded-lg shadow-lg p-4 h-full">

            <h2 className="text-lg font-semibold text-white mb-4">Top Products with Highest CVEs</h2>
            {products.length === 0 ? (
              <p className="text-sm text-gray-300 mb-4">Please add something to your watchlist.</p>
            ) : (
              <p className="text-sm text-[#00CBF0]">Displaying top products with highest CVEs</p>
            )}
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={products}
                  dataKey="CVEs"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  innerRadius={60}
                  offsetRadius={10}
                  stroke="#000000"
                  label={(entry) => entry.name}
                >
                  {products.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>

  );
}