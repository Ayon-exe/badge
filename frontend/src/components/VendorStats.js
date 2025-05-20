// Import necessary components and libraries
import Link from 'next/link';
import { useParams } from "next/navigation";
import { Wrench, Swords, TrendingUp, Loader2, Award, Info, CheckCircle } from "lucide-react";
import {
  PieChart,
  BarChart,
  RadialBarChart,
  RadialBar,
  Legend,
  Pie,
  CartesianGrid,
  YAxis,
  XAxis,
  Bar,
  Cell,
  LabelList,
} from "recharts";
import Block from "@/components/Block";
import { useEffect, useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

import {
  ChartConfig,
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart";

// Define chart configurations
const chartConfigs = {
  chartConfig1: {
    vulnerabilities: {
      label: "CVEs",
    },
    daily: {
      label: "24 Hours",
      color: "hsl(var(--chart-1))",
    },
    weekly: {
      label: "7 Days",
      color: "hsl(var(--chart-2))",
    },
    monthly: {
      label: "30 Days",
      color: "hsl(var(--chart-3))",
    },
  },
  chartConfig2: {
    vulnerabilities: {
      label: "Vulnerabilities",
      color: "hsl(var(--chart-2))",
    },
    label: {
      color: "white",
    },
  },
  chartConfig3: {
    vulnerabilities: {
      label: "CVEs",
    },
    daily: {
      label: "24 Hours",
      color: "hsl(var(--chart-1))",
    },
    weekly: {
      label: "7 Days",
      color: "hsl(var(--chart-2))",
    },
    monthly: {
      label: "30 Days",
      color: "hsl(var(--chart-3))",
    },
  },
};

// Define the VendorStats component
export function VendorStats(vendorName) {
  // Initialize state variables
  const vendor = vendorName.data;
  const [data, setData] = useState(null);
  const [barData, setBarData] = useState(null);
  const [vendorBoxData, setvendorBoxData] = useState(null);
  const [radialData, setRadialData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState({
    weightedAverage: null,
    unassigned: null,
    totalCount: null,
  });
  const [topSevereCves, setTopSevereCves] = useState(null);

  // Fetch data from API
  useEffect(() => {
    const fetchData = async () => {
      try {
        let response = await fetch(
          `${process.env.SERVER_URL}/api/cve/attackVector/stats?vendor=${vendor}`
        );
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        let jsonData = await response.json();
        const mappedData = mapData(jsonData);
        console.log(mappedData);
        setData(mappedData);

        response = await fetch(
          `${process.env.SERVER_URL}/api/cve/cvss/stats?vendor=${vendor}`
        );
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        jsonData = await response.json();
        setStats({
          totalCount: jsonData.totalCount,
        });
        console.log("befor mapped data: ", jsonData);
        const mappedBarData = mapBarData(jsonData);
        console.log("mapped data: ", mappedBarData);
        setBarData(mappedBarData);

        const response1 = await fetch(
          `${process.env.SERVER_URL}/api/cve/cvss/stats`
        );
        if (!response1.ok) {
          throw new Error("Network response was not ok");
        }
        const jsonData1 = await response1.json();

        setStats({
          weightedAverage: jsonData.weightedAverage,
        });

        response = await fetch(
          `${process.env.SERVER_URL}/api/cve/fixes/stats?vendor=${vendor}`
        );
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        jsonData = await response.json();
        const mappedRadialData = mapRadialData(jsonData);
        setRadialData(mappedRadialData);

        response = await fetch(
          `${process.env.SERVER_URL}/api/cve/boxData/stats?vendor=${vendor}`
        );
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        jsonData = await response.json();
        setvendorBoxData(jsonData);

        // response = await fetch(`${process.env.SERVER_URL}/api/cve/boxData/stats?vendor=${vendor}`);
        // if (!response.ok) {
        //   throw new Error("Network response was not ok");
        // }
        // jsonData = await response.json();
        // const mappedRadialData = mapRadialData(jsonData)
        // setRadialData(mappedRadialData);

        response = await fetch(
          `${process.env.SERVER_URL}/api/cve/top-severe-cves?vendor=${vendor}`
        );
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        jsonData = await response.json();
        setTopSevereCves(jsonData);

      } catch (error) {
        setError(error.message);
        console.error("Error fetching data:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  const truncateText = (text, maxLength) => {
    if (text.length <= maxLength) {
      return text;
    }
    return text.substring(0, maxLength - 3) + '...';
  };

  const mapRadialData = (rawData) => {
    return [
      {
        name: "Fixed",
        value: rawData.fixed,
        fill: "hsl(var(--chart-1))",
      },
      {
        name: "Total",
        value: rawData.total,
        fill: "hsl(var(--chart-2))",
      },
    ];
  };

  const mapBarData = (rawData) => {
    const { scoreRanges, totalCount, weightedAverage } = rawData;

    return [
      {
        name: "0-1",
        value: scoreRanges["0-1"] || 0,
        fill: "hsl(var(--chart-1))",
      },
      {
        name: "1-2",
        value: scoreRanges["1-2"] || 0,
        fill: "hsl(var(--chart-2))",
      },
      {
        name: "2-3",
        value: scoreRanges["2-3"] || 0,
        fill: "hsl(var(--chart-1))",
      },
      {
        name: "3-2",
        value: scoreRanges["3-2"] || 0,
        fill: "hsl(var(--chart-2))",
      },
      {
        name: "4-5",
        value: scoreRanges["4-5"] || 0,
        fill: "hsl(var(--chart-1))",
      },
      {
        name: "5-6",
        value: scoreRanges["5-6"] || 0,
        fill: "hsl(var(--chart-2))",
      },
      {
        name: "6-7",
        value: scoreRanges["6-7"] || 0,
        fill: "hsl(var(--chart-1))",
      },
      {
        name: "7-8",
        value: scoreRanges["7-8"] || 0,
        fill: "hsl(var(--chart-2))",
      },
      {
        name: "8-9",
        value: scoreRanges["8-9"] || 0,
        fill: "hsl(var(--chart-1))",
      },
      {
        name: "9+",
        value: scoreRanges["9+"] || 0,
        fill: "hsl(var(--chart-2))",
      },
    ];
  };

  const mapData = (rawData) => {
    const attackVectorTypes = new Set(rawData.map((item) => item.attackVector));
    const chartColors = ["--chart-1", "--chart-2", "--chart-3", "--chart-4"];

    return Array.from(attackVectorTypes).reduce((acc, attackVector, index) => {
      const item = rawData.find((i) => i.attackVector === attackVector);
      if (item && item.attackVector !== null) {
        acc.push({
          name: attackVector || "Unknown",
          value: item.count,
          fill: `hsl(var(${chartColors[index % chartColors.length]}))`,
        });
      }
      return acc;
    }, []);
  };

  // Render loading indicator if data is not loaded
  if (isLoading) {
    return (
      <Card className=" flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm">
        <CardContent className="flex items-center justify-center min-h-[300px] min-w-[300px]">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  // Render error message if data loading fails
  if (error) {
    return (
      <Card className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm">
        <CardContent className="flex i  tems-center justify-center min-h-[300px] text-destructive">
          Error loading data: {error}
        </CardContent>
      </Card>
    );
  }

  // Prepare pie chart data
  const pieChartData = data || [
    {
      name: "Network",
      value: data?.attackVectors?.network || 10,
      fill: "hsl(var(--chart-1))", // Custom color for Network sector
    },
    {
      name: "Application",
      value: data?.attackVectors?.application || 20,
      fill: "hsl(var(--chart-2))", // Custom color for Application sector
    },
    {
      name: "Physical",
      value: data?.attackVectors?.physical || 30,
      fill: "hsl(var(--chart-3))", // Custom color for Physical sector
    },
    {
      name: "Environmental",
      value: data?.attackVectors?.environmental || 40,
      fill: "hsl(var(--chart-4))", // Custom color for Environmental sector
    },
  ];

  // Render the component
  return (
    <>
      {/* Main */}
      <div className="flex flex-col w-screen text-white justify-center items-center py-2 bg-blue-950/30 backdrop-blur-md shadow-lg rounded-lg">
        <div className="w-3/4">
          <Block
            title1={"Total Vulnerabilities"}
            desc1={vendorBoxData.total_vuln != null ? parseFloat(vendorBoxData.total_vuln).toLocaleString("en-GB") : "Loading..."}
            title2={"Vulnerabilities Exploited"}
            desc2={vendorBoxData.vuln_exploited != null ? parseFloat(vendorBoxData.vuln_exploited).toLocaleString("en-GB") : "Loading..."}
            title3={"Avg. CVSS Score"}
            desc3={vendorBoxData.weighted_avg != null ? parseFloat(vendorBoxData.weighted_avg).toFixed(2) : "Loading..."}
            title4={"Vulnerabilities this year"}
            desc4={vendorBoxData.vuln_this_year != null ? parseFloat(vendorBoxData.vuln_this_year).toLocaleString("en-GB") : "Loading..."}
            title5={"Vulnerabilities this month"}
            desc5={vendorBoxData.vuln_this_month != null ? parseFloat(vendorBoxData.vuln_this_month).toLocaleString("en-GB") : "Loading..."}
          />
        </div>
        {/* First row: Breakdown (1/3) and Top 3 CVE's (2/3) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 m-2 w-full md:w-3/4 items-stretch">
          {/* Breakdown of all Attack Vectors */}
          <div className="col-span-1">
            <Card className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm h-full">
              <CardHeader className="pb-1">
                <CardDescription className="flex flex-row text-[#00CBF0] text-lg font-semibold">
                  <Swords className="mr-2" size={18} />
                  Breakdown of all Attack Vectors:
                </CardDescription>
              </CardHeader>
              <CardContent className="flex-1 p-2 flex justify-center">
                {pieChartData.length > 0 ? (
                  <ChartContainer config={chartConfigs.chartConfig1} className="mx-auto aspect-square min-h-[80px]">
                    <PieChart width={300} height={300}>
                      <Pie
                        data={pieChartData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        fill="#8884d8"
                        label={(entry) => entry.name}
                      />
                      <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel nameKey="name" valueKey={(entry) => entry.name} />} />
                    </PieChart>
                  </ChartContainer>
                ) : (
                  <div className="text-center text-xl text-muted-foreground">
                    No attack vectors found.
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Top 3 Most Severest CVE's */}
          <div className="col-span-2">
            <Card className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm h-full">
              <CardHeader className="pb-1">
                <CardDescription className="flex flex-row text-[#00CBF0] text-lg font-semibold">
                  <Award className="mr-2" size={18} />
                  Top 3 Most Severest CVE's
                </CardDescription>
              </CardHeader>
              <CardContent className="flex-1 p-2">
                {topSevereCves &&
                  topSevereCves.slice(0, 3).map((cve, index) => {
                    // Define a helper function for conditional color coding
                    const getCVSSColor = (score) => {
                      if (score >= 9) return "text-red-500";
                      if (score >= 7) return "text-orange-500";
                      if (score >= 4) return "text-yellow-500";
                      return "text-green-500";
                    };

                    return (
                      <Link key={index} href={`/cve/${cve.cve_id}`}>
                        <div className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm p-4 mb-2 cursor-pointer hover:border-[#00B7EF] hover:border-2 transition duration-300">
                          <CardTitle className="text-lg font-bold text-[#00B7EF]">{cve.cve_id}</CardTitle>
                          <div className="flex justify-between">
                            <CardDescription
                              className="text-sm max-w-md overflow-wrap break-words"
                              style={{ maxWidth: "450px" }}
                            >
                              {truncateText(cve.description, 200)}
                            </CardDescription>
                            <div className="flex flex-col items-center ml-4">
                              <span className={`text-xl font-bold ${getCVSSColor(cve.cvss_score)}`}>
                                {cve.cvss_score}
                              </span>
                              <span className="text-xs text-gray-400">CVSS Score</span>
                            </div>
                          </div>
                        </div>
                      </Link>
                    );
                  })}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Second row: Distribution and CVE's with/without fix */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 m-2 w-3/4">
          {/* Distribution of vulnerabilities by CVSS scores */}
          <Card className="rounded-lg bg-slate-950/75 backdrop-blur-sm w-full">
            <CardHeader >
              <CardDescription className="flex flex-row text-[#00CBF0] text-lg font-semibold">
    { /* <TrendingUp size={24} className="mr-2" /> */ }
                Distribution of vulnerabilities by CVSS scores
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ChartContainer className="min-h-[120px]" config={chartConfigs.chartConfig2}>
                <BarChart
                  accessibilityLayer
                  data={barData}
                  layout="vertical"
                  margin={{ right: 16, left: 32 }}
                >
                  <CartesianGrid horizontal={false} />
                  <YAxis dataKey="name" type="category" tickLine={false} tickMargin={10} axisLine={false} tickFormatter={(value) => value.slice(0, 3)} hide />
                  <XAxis dataKey="value" type="number" hide />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent indicator="line" />} />
                  <Bar dataKey="value" layout="vertical" radius={4} fill="hsl(var(--chart-2))">
                    <LabelList dataKey="name" position="left" offset={8} className="fill-[--color-label]" fontSize={12} />
                    <LabelList dataKey="value" position="right" offset={8} className="fill-foreground" fontSize={12} />
                  </Bar>
                </BarChart>
              </ChartContainer>
              <CardFooter className="flex flex-col gap-1 text-sm mt-5 pb-0">
                <div className="border border-gray-300 rounded-lg shadow-md">
                  <table className="table-fixed w-full text-sm">
                    <thead>
                      <tr>
                        <th className="px-4 items-center justify-between w-2/3 py-2 text-left font-semibold text-sm">Severity</th>
                        <th className="px-4 items-center justify-between w-1/3 py-2 text-right font-semibold text-sm">Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td className="px-4 py-1">
                          <div className="flex items-center">
    { /* <CloudAlert className="text-red-500 mr-2" /> */ }
                            High Severity
                          </div>
                        </td>
                        <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{barData.find((item) => item.name === "9+").value}</td>
                      </tr>
                      <tr>
                        <td className="px-4 py-1">
                          <div className="flex items-center">
    { /* <TriangleAlert className="text-orange-500 mr-2" /> */ }
                            Medium Severity
                          </div>
                        </td>
                        <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{barData.find((item) => item.name === "7-8").value}</td>
                      </tr>
                      <tr>
                        <td className="px-4 py-1">
                          <div className="flex items-center">
    { /* <Info className="text-yellow-500 mr-2" /> */ }
                            Low Severity
                          </div>
                        </td>
                        <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{barData.find((item) => item.name === "4-5").value + barData.find((item) => item.name === "5-6").value}</td>
                      </tr>
                      <tr>
                        <td className="px-4 py-1">
                          <div className="flex items-center">
    { /* <CheckCircle className="text-green-500 mr-2" /> */ }
                            Harmless Severity
                          </div>
                        </td>
                        <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{barData.find((item) => item.name === "0-1").value + barData.find((item) => item.name === "1-2").value + barData.find((item) => item.name === "2-3").value}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </CardFooter>
            </CardContent>
          </Card>

          {/* CVE's with or without fix */}
          <Card className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm w-full">
            <CardHeader className="pb-1">
              <CardDescription className="flex flex-row text-[#00CBF0] text-lg font-semibold">
                <Wrench className="mr-2" size={18} />
                CVE's with or without fix
              </CardDescription>
            </CardHeader>
            <CardContent className="flex-1 p-2 p-2 flex justify-center items-center">
              <ChartContainer config={chartConfigs.chartConfig3} className="mx-auto min-h-[120px]">
                <RadialBarChart
                  width={300}
                  height={300}
                  data={radialData}
                  startAngle={0}
                  endAngle={360}
                  innerRadius="50%"
                  outerRadius="100%"
                  max="100"
                  barSize={20}
                  fill="#57C3FF"
                  background="#0B1739"
                >
                  <ChartTooltip
                    cursor={false}
                    content={
                      <ChartTooltipContent
                        hideLabel
                        nameKey="name"
                        valueKey={(entry) => {
                          const total = radialData[1].value;
                          const value = entry.value;
                          return `${((value / total) * 100).toFixed(2)}%`;
                        }}
                      />
                    }
                  />
                  <RadialBar dataKey="value" background cornerRadius={30}>
                    <LabelList dataKey={(entry) => entry.value} position="insideStart" fill="#fff" fontSize={12} />
                  </RadialBar>
                  <Legend
                    iconSize={10}
                    layout="vertical"
                    verticalAlign="middle"
                    position="inside"
                    wrapperStyle={{ top: "50%", right: "0%" }}
                    formatter={(value, entry, index) => {
                      const total = radialData[1].value;
                      if (index === 0) {
                        const percentage = ((radialData[0].value / total) * 100).toFixed(2);
                        return `Fixed: ${percentage}%`;
                      } else {
                        const percentage = ((radialData[1].value / total) * 100).toFixed(2);
                        return `Total: ${percentage}%`;
                      }
                    }}
                  />
                </RadialBarChart>
              </ChartContainer>
            </CardContent>
          </Card>
        </div>
      </div>


    </>
  );
}

export default VendorStats;
