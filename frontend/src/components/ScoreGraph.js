// "use client";

// import { TimerIcon, TrendingUp, Loader2 } from "lucide-react";
// // import { LabelList, RadialBar, Legend, RadialBarChart } from "recharts";
// import { useEffect, useState } from "react";

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

// const chartConfig = {
//   vulnerabilities: {
//     label: "CVEs",
//   },
//   daily: {
//     label: "24 Hours",
//     color: "hsl(var(--chart-1))",
//   },
//   weekly: {
//     label: "7 Days",
//     color: "hsl(var(--chart-2))",
//   },
//   monthly: {
//     label: "",
//     // color: "hsl(var(--chart-3))",
//     color:"red",
//   },
// };

// export function ScoreGraph() {
//   const [data, setData] = useState(null);
//   const [isLoading, setIsLoading] = useState(true);
//   const [error, setError] = useState(null);

//   useEffect(() => {
//     const fetchData = async () => {
//       try {
//         const response = await fetch(`${process.env.SERVER_URL}/api/cve/stats`);
//         if (!response.ok) {
//           throw new Error("Network response was not ok");
//         }
//         const jsonData = await response.json();
//         setData(jsonData);
//       } catch (error) {
//         setError(error.message);
//         console.error("Error fetching data:", error);
//       } finally {
//         setIsLoading(false);
//       }
//     };

//     fetchData();
//   }, []);

//   if (isLoading) {
//     return (
//       <Card className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm">
//         <CardContent className="flex items-center justify-center min-h-[300px]">
//           <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
//         </CardContent>
//       </Card>
//     );
//   }

//   if (error) {
//     return (
//       <Card className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm">
//         <CardContent className="flex items-center justify-center min-h-[300px] text-destructive">
//           Error loading data: {error}
//         </CardContent>
//       </Card>
//     );
//   }

//   const chartData = [
//     {
//       name: "",
//       value: data?.newAndUpdatedCVEs?.updatedLast30Days || 100,
//       // fill: "var(--color-monthly)",
//       fill: "#0B1739",
//     },
//     {
//       name: "",
//       value: data?.newAndUpdatedCVEs?.updatedLast7Days || 0,
//       fill: "#57C3FF",
//     },
//     {
//       name: "",
//       value: data?.newAndUpdatedCVEs?.updatedSinceYesterday || 100,
//       fill: "#FF579A",
//     },
//   ];
//   const style = {
//     top: '50%',
//     right: 0,
//     transform: 'translate(0, -50%)',
//     lineHeight: '24px',
//   };
//   return (
//     <Card className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm">
//       <CardHeader className="pb-0">
//         <CardDescription className="flex flex-row text-[#00CBF0] text-lg font-semibold">
//           <TimerIcon className="mr-2" size={18} />
//           Your Readiness Score
//         </CardDescription>
//       </CardHeader>
//       <CardContent className="flex-1 pb-0">
//         <ChartContainer
//           config={chartConfig}
//           className="mx-auto aspect-square min-h-[120px]"
//         >
//           <RadialBarChart
//             data={chartData}
//             startAngle={0}
//             endAngle={360}
//             innerRadius="30%"
//             outerRadius="100%"
//             barSize={20}
//           >
//             <ChartTooltip
//               cursor={false}
//               content={
//                 <ChartTooltipContent
//                   hideLabel
//                   nameKey="name"
//                   valueKey="value"
//                 />
//               }
//             />
//             <RadialBar dataKey="value" background cornerRadius={30}>
//               <LabelList
//                 dataKey="name"
//                 position="insideStart"
//                 fill="#fff"
//                 fontSize={12}
//               />
//             </RadialBar>
//             <Legend iconSize={10} layout="vertical" verticalAlign="middle" wrapperStyle={style} />
//           </RadialBarChart>
//         </ChartContainer>
//       </CardContent>
//       {/* <CardFooter className="flex flex-col items-start gap-2">
//         <div className="text-md font-medium">Statistics:</div>
//         <div className="grid grid-cols-3 gap-4 text-md">
//           <div>
//             <div className="font-medium">24 Hours</div>
//             <div>{data?.newAndUpdatedCVEs?.updatedSinceYesterday}</div>
//           </div>
//           <div>
//             <div className="font-medium">7 Days</div>
//             <div>{data?.newAndUpdatedCVEs?.updatedLast7Days}</div>
//           </div>
//           <div>
//             <div className="font-medium">30 Days</div>
//             <div>{data?.newAndUpdatedCVEs?.updatedLast30Days}</div>
//           </div>
//         </div>
//       </CardFooter> */}
//     </Card>
//   );
// }

// export default ScoreGraph;

// ------------------------------------------------
import React from "react";
import { RadialBarChart, RadialBar, Legend } from "recharts";

const data = [
  { name: "Ring 1", value: 100, fill: "#0B1739" },
  { name: "Current Score", value: 80, fill: "#57C3FF" },
  { name: "Potential Score", value: 90, fill: "#FF579A" },
];

const style = {
  left: 200,
  lineHeight: "24px",
};

const ScoreGraph = () => {
  return (
    <div style={{ position: "relative", width: "100%", height: "300px" }}>
      <RadialBarChart
        width={200}
        height={200}
        innerRadius="80%"
        outerRadius="100%"
        data={data}
        startAngle={180}
        endAngle={-180}
        
      >
        <RadialBar minAngle={15} clockwise dataKey="value" background={{ fill: "#0B1739" }} />
        <Legend
          iconSize={10}
          width={120}
          height={140}
          layout="vertical"
          verticalAlign="middle"
          wrapperStyle={style}
        />
      </RadialBarChart>

      {/* Text in the center */}
      <div
        style={{
          position: "absolute",
          top: 25,
          left: 70,
          textAlign: "center",
          color: "#FFFFFF",
          fontSize: "100px",
        }}
      >
      <strong>8</strong>
      </div>
    </div>
  );
};

export default ScoreGraph;