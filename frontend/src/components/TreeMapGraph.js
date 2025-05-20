// "use client";

// import * as React from "react";
// import {
//   Area,
//   AreaChart,
//   Bar,
//   BarChart,
//   CartesianGrid,
//   XAxis,
//   YAxis,
// } from "recharts";

// import {
//   Card,
//   CardContent,
//   CardDescription,
//   CardFooter,
//   CardHeader,
//   CardTitle,
// } from "@/components/ui/card";
// import {
//   ChartConfig,
//   ChartContainer,
//   ChartLegend,
//   ChartLegendContent,
//   ChartTooltip,
//   ChartTooltipContent,
// } from "@/components/ui/chart";

// export const description = "An interactive bar chart";

// const chartData = [
//   {
//     date: "2014",
//     Total: 3425,
//     Overflow: 1100,
//     Memory_Corruption: 800,
//     SQL_Injection: 200,
//     XSS: 650,
//     Directory_Traversal: 150,
//     File_Inclusion: 225,
//     CSRF: 150,
//     XXE: 50,
//     SSRF: 100
//   },
//   {
//     date: "2015",
//     Total: 3680,
//     Overflow: 800,
//     Memory_Corruption: 1000,
//     SQL_Injection: 250,
//     XSS: 850,
//     Directory_Traversal: 180,
//     File_Inclusion: 250,
//     CSRF: 175,
//     XXE: 75,
//     SSRF: 100
//   },
//   {
//     date: "2016",
//     Total: 3950,
//     Overflow: 500,
//     Memory_Corruption: 1200,
//     SQL_Injection: 300,
//     XSS: 1100,
//     Directory_Traversal: 200,
//     File_Inclusion: 275,
//     CSRF: 175,
//     XXE: 100,
//     SSRF: 100
//   },
//   {
//     date: "2017",
//     Total: 5900,
//     Overflow: 2500,
//     Memory_Corruption: 1500,
//     SQL_Injection: 400,
//     XSS: 600,
//     Directory_Traversal: 250,
//     File_Inclusion: 275,
//     CSRF: 175,
//     XXE: 100,
//     SSRF: 100
//   },
//   {
//     date: "2018",
//     Total: 6350,
//     Overflow: 2000,
//     Memory_Corruption: 2000,
//     SQL_Injection: 450,
//     XSS: 800,
//     Directory_Traversal: 300,
//     File_Inclusion: 400,
//     CSRF: 200,
//     XXE: 100,
//     SSRF: 100
//   },
//   {
//     date: "2019",
//     Total: 6900,
//     Overflow: 1200,
//     Memory_Corruption: 2000,
//     SQL_Injection: 600,
//     XSS: 1800,
//     Directory_Traversal: 350,
//     File_Inclusion: 450,
//     CSRF: 250,
//     XXE: 125,
//     SSRF: 125
//   },
//   {
//     date: "2020",
//     Total: 7250,
//     Overflow: 1200,
//     Memory_Corruption: 2200,
//     SQL_Injection: 650,
//     XSS: 1800,
//     Directory_Traversal: 400,
//     File_Inclusion: 450,
//     CSRF: 275,
//     XXE: 150,
//     SSRF: 125
//   },
//   {
//     date: "2021",
//     Total: 9875,
//     Overflow: 1500,
//     Memory_Corruption: 2500,
//     SQL_Injection: 800,
//     XSS: 2800,
//     Directory_Traversal: 600,
//     File_Inclusion: 700,
//     CSRF: 500,
//     XXE: 175,
//     SSRF: 300
//   },
//   {
//     date: "2022",
//     Total: 12800,
//     Overflow: 1800,
//     Memory_Corruption: 3400,
//     SQL_Injection: 1800,
//     XSS: 3400,
//     Directory_Traversal: 750,
//     File_Inclusion: 800,
//     CSRF: 400,
//     XXE: 200,
//     SSRF: 250
//   },
//   {
//     date: "2023",
//     Total: 15900,
//     Overflow: 1800,
//     Memory_Corruption: 2600,
//     SQL_Injection: 2000,
//     XSS: 5200,
//     Directory_Traversal: 1400,
//     File_Inclusion: 1500,
//     CSRF: 600,
//     XXE: 300,
//     SSRF: 500
//   },
//   {
//     date: "2024",
//     Total: 18300,
//     Overflow: 1800,
//     Memory_Corruption: 2500,
//     SQL_Injection: 2200,
//     XSS: 7400,
//     Directory_Traversal: 1500,
//     File_Inclusion: 1600,
//     CSRF: 600,
//     XXE: 300,
//     SSRF: 400
//   }
// ];

// const chartConfig = {
//   views: {
//     label: "Vulnerabilty",
//   },
//   Total: {
//     label: "Total",
//     color: "hsl(var(--chart-1))",
//   },
//   Overflow: {
//     label: "Mobile",
//     color: "hsl(var(--chart-2))",
//   },
//   Memory_Corruption: {
//     label: "Memory Corruption",
//     color: "hsl(var(--chart-3))",
//   },
//   SQL_Injection: {
//     label: "SQL Injection",
//     color: "hsl(var(--chart-4))",
//   },
//   XSS: {
//     label: "SQL Injection",
//     color: "hsl(var(--chart-5))",
//   },
//   Directory_Traversal: {
//     label: "SQL Injection",
//     color: "hsl(var(--chart-1))",
//   },
//   File_Inclusion: {
//     label: "SQL Injection",
//     color: "hsl(var(--chart-2))",
//   },
//   CSRF: {
//     label: "SQL Injection",
//     color: "hsl(var(--chart-3))",
//   },
//   XXE: {
//     label: "SQL Injection",
//     color: "hsl(var(--chart-4))",
//   },
//   SSRF: {
//     label: "SQL Injection",
//     color: "hsl(var(--chart-5))",
//   },
// };

// export function TopCompaniesGraph() {
//   const [activeChart, setActiveChart] = React.useState("Total");

//   return (
//     <Card className="w-full md:w-2/3  rounded-lg bg-slate-950/75 backdrop-blur-sm">
//       <CardHeader className="flex flex-col items-stretch space-y-0 border-b p-0 sm:flex-col">
//         <div className="flex flex-1 flex-col justify-center gap-1 px-6 py-5 sm:py-6">
//         <CardTitle className="text-2xl">Top Companies</CardTitle>
//           <CardDescription className="text-[#00CBF0] text-lg font-semibold">
//             Companies with the highest number of CVE's reported.
//           </CardDescription>
          
//         </div>
//       </CardHeader>
//       <CardContent className="px-2 sm:p-6">
//         <ChartContainer className=" md:min-h-[120px]" config={chartConfig}>
//           <AreaChart
//             accessibilityLayer
//             data={chartData}
//             margin={{
//               left: 0,
//               right: 18,
//             }}
//           >
//             <CartesianGrid vertical={false} />
//             <YAxis tickLine={false} axisLine={false} />
//             <XAxis
//               dataKey="date"
//               tickLine={false}
//               axisLine={false}
//               tickMargin={12}
//               tickFormatter={(value) => value.slice(0, 4)}
//             />
//             <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
//             <ChartLegend position content={<ChartLegendContent />} />
//             <defs>
//               <linearGradient
//                 id={`fill${activeChart}`}
//                 x1="0"
//                 y1="0"
//                 x2="0"
//                 y2="1"
//               >
//                 <stop
//                   offset="5%"
//                   stopColor={`var(--color-${activeChart})`}
//                   stopOpacity={0.8}
//                 />
//                 <stop
//                   offset="95%"
//                   stopColor={`var(--color-${activeChart})`}
//                   stopOpacity={0.1}
//                 />
//               </linearGradient>
//             </defs>
//             <Area
//               dataKey={activeChart}
//               type="natural"
//               fill={`url(#fill${activeChart})`}
//               fillOpacity={0.4}
//               stroke={`var(--color-${activeChart})`}
//               stackId="a"
//             />
//           </AreaChart>
//         </ChartContainer>
//       </CardContent>
//       <CardFooter className="flex flex-col items-stretch space-y-0 border-b p-0 sm:flex-col">
//         <div className="grid grid-cols-5 mx-4 my-2">
//           {[
//             "Total",
//             "Overflow",
//             "Memory_Corruption",
//             "SQL_Injection",
//             "XSS",
//             "Directory_Traversal",
//             "File_Inclusion",
//             "CSRF",
//             "XXE",
//             "SSRF",
//           ].map((key) => {
//             const chart = key;
//             return (
//               <button
//                 key={chart}
//                 data-active={activeChart === chart}
//                 className="relative z-30 flex justify-center gap-1 rounded-full px-4 py-4 text-left data-[active=true]:bg-muted/50"
//                 onClick={() => setActiveChart(chart)}
//               >
//                 <span className="text-xs text-muted-foreground">
//                   {/* {chartConfig[chart].label} */}
//                   {chart}
//                 </span>
//               </button>
//             );
//           })}
//         </div>
//       </CardFooter>
//     </Card>
//   );
// }


import * as React from "react";
import { Treemap, ResponsiveContainer } from 'recharts';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const chartData = [
  {
    "name": "Root",
    "children": [
      {
        "name": "Microsoft",
        "value": 12443
      },
      {
        "name": "Oracle",
        "value": 9810
      },
      {
        "name": "IBM",
        "value": 7373
      },
      {
        "name": "Google",
        "value": 11705
      },
      {
        "name": "Apple",
        "value": 7617
      },
      {
        "name": "Cisco",
        "value": 6390
      },
      {
        "name": "Adobe",
        "value": 6071
      },
      {
        "name": "Mozilla",
        "value": 3145
      },
      {
        "name": "Linux",
        "value": 6855
      },
      {
        "name": "Debian",
        "value": 9015
      }
    ]
  },
];

const colors = ["#FF69B4", "#33CC33", "#6666CC", "#FF9900", "#CC33CC", "#33CCCC", "#CC6666", "#66CCCC", "#CCCC33", "#33CC66"];

export function TopCompaniesGraph() {
  return (
    <Card className="w-full md:w-2/3  rounded-lg bg-slate-950/75 backdrop-blur-sm">
      <CardHeader className="flex flex-col items-stretch space-y-0 border-b p-0 sm:flex-col">
        <div className="flex flex-1 flex-col justify-center gap-1 px-6 py-5 sm:py-6">
          <CardTitle className="text-2xl">Top Companies</CardTitle>
          <CardDescription className="text-[#00CBF0] text-lg font-semibold">
            Companies with the highest number of CVE's reported.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="px-2 sm:p-6">
        <ResponsiveContainer width="100%" height={400}>
          <Treemap
            data={chartData[0].children}
            dataKey="value"
            nameKey="name"
            fill="#8884d8"
            stroke="#fff"
            rectStyle={{
              fill: (props) => colors[props.index % colors.length],
              stroke: "#fff",
              strokeWidth: 1,
            }}
            labelStyle={{
              fontSize: 12,
              fill: "#333",
            }}
          >
            {chartData[0].children.map((item, index) => (
              <text
                key={item.name} // or use index if you don't have a unique identifier
                x={item.x + item.width / 2}
                y={item.y + item.height / 2 + 15}
                textAnchor="middle"
                fill="#333"
                fontSize={12}
              >
                {item.value}
              </text>
            ))}
          </Treemap>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}