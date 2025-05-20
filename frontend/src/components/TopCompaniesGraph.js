import * as React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
} from "recharts";

const data = [
  {
    name: "Page A",
    uv: 4000,
    pv: 2400,
    amt: 2400,
  },
  {
    name: "Page B",
    uv: 3000,
    pv: 1398,
    amt: 2210,
  },
  {
    name: "Page C",
    uv: 2000,
    pv: 9800,
    amt: 2290,
  },
  {
    name: "Page D",
    uv: 2780,
    pv: 3908,
    amt: 2000,
  },
  {
    name: "Page E",
    uv: 1890,
    pv: 4800,
    amt: 2181,
  },
];

const colors = [
  "bg-red-500",
  "bg-green-500",
  "bg-blue-500",
  "bg-yellow-500",
  "bg-orange-500",
  "bg-purple-500",
  "bg-pink-500",
  "bg-gray-500",
  "bg-white",
];

const Square = ({ color }) => {
  return (
    <div className={`${color} h-48 w-48 m-4 p-4`}>
      <BarChart
        width={200}
        height={200}
        data={data}
        margin={{
          top: 5,
          right: 30,
          left: 20,
          bottom: 5,
        }}
      >
        <XAxis  />
        <YAxis />
        <Bar dataKey="uv" fill="#000000" />
      </BarChart>
    </div>
  );
};

export function TopCompaniesGraph() {
  return (
    <div>
      <h1>Top Companies</h1>
      <h3>Companies with the highest recorded number of CVE's</h3>
      
      <div
        className="scrollbar"
        style={{
          maxWidth: '75%',
          overflowY: 'hidden',
          overflowX: 'auto',
          marginLeft: "50px"
        }}
      >
        <div
          className="flex flex-row"
          style={{
            display: 'flex',
            flexDirection: 'row',
            flexWrap: 'nowrap',
            width: 'max-content'
          }}
        >
          {colors.map((color, index) => (
            <Square key={index} color={color} />
          ))}
        </div>
      </div>
    </div>
  );
}

export default TopCompaniesGraph;