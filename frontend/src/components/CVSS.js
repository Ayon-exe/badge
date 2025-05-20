"use client";
import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  XAxis,
  YAxis,
  Cell,
} from "recharts";
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
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart";
//import { TrendingUp, Loader2, CloudAlert, TriangleAlert, Info, CheckCircle } from 'lucide-react';
import { Loader2 } from 'lucide-react';
import { useEffect, useState } from "react";

const transformScoreData = (data) => {
  // Convert scoreRanges object into array format
  return Object.entries(data.scoreRanges).map(([score, vulnerabilities]) => ({
    score,
    vulnerabilities,
  }));
};

const chartConfig = {
  vulnerabilities: {
    label: "Vulnerabilities",
    color: "hsl(var(--chart-2))",
  },
  label: {
    color: "white",
  },
};

export function BarGraph() {
  const [data, setData] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState({ weightedAverage: null });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response1 = await fetch(`${process.env.SERVER_URL}/api/cve/cvss/stats`);
        if (!response1.ok) {
          throw new Error("Network response was not ok");
        }
        const jsonData1 = await response1.json(); // Add await here
        if (jsonData1.scoreRanges) { // Add null check here
          const transformedData = transformScoreData(jsonData1);
          setData(transformedData);
        } else {
          setError("Invalid data format");
        }
  
        const response2 = await fetch(`${process.env.SERVER_URL}/api/cve/weaknesses/stats`);
        if (!response2.ok) {
          throw new Error("Network response was not ok");
        }
        const jsonData2 = await response2.json();
        console.log("Fetched data:", jsonData2);
  
        if (Array.isArray(jsonData2)) {
          const initialTotal = jsonData2.reduce((acc, item) => acc + item.Total, 0);
          setStats({
            weightedAverage: jsonData1.weightedAverage,
            totalCount: jsonData1.totalCount,
            scoreRanges: jsonData1.scoreRanges,
            unassigned: jsonData1.totalCount - initialTotal,
            initial: initialTotal,
          });
        } else {
          setError("Invalid data format");
        }
      } catch (error) {
        setError(error.message);
        console.error("Error fetching data:", error);
      } finally {
        setIsLoading(false);
      }
    };
  
    fetchData();
  }, []);

  if (isLoading) {
    return (
      <Card className="rounded-lg bg-slate-950/75 backdrop-blur-sm">
        <CardContent className="flex items-center justify-center min-h-[300px]">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="rounded-lg bg-slate-950/75 backdrop-blur-sm">
        <CardContent className="flex items-center justify-center min-h-[300px] text-destructive">
          Error loading data: {error}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="rounded-lg bg-slate-950/75 backdrop-blur-sm">
      <CardHeader>
        <CardDescription className="flex flex-row text-[#00CBF0] text-lg font-semibold">
    { /* <TrendingUp size={24} className="mr-2" /> */ }
          Distribution of vulnerabilities by CVSS scores since 2014.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer className="min-h-[120px]" config={chartConfig}>
          <BarChart
            accessibilityLayer
            data={data}
            layout="vertical"
            margin={{
              right: 16,
              left: 32,
            }}
          >
            <CartesianGrid horizontal={false} />
            <YAxis
              dataKey="score"
              type="category"
              tickLine={false}
              tickMargin={10}
              axisLine={false}
              tickFormatter={(value) => value.slice(0, 3)}
              hide
            />
            <XAxis dataKey="vulnerabilities" type="number" hide />
            <ChartTooltip
              cursor={false}
              content={<ChartTooltipContent indicator="line" />}
            />
            <Bar
              dataKey="vulnerabilities"
              layout="vertical"
              radius={4}
              barSize={20}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill="#FF3C9D" />
              ))}
              <LabelList
                dataKey="score"
                position="left"
                offset={8}
                className="fill-(--color-label)"
                fontSize={12}
              />
              <LabelList
                dataKey="vulnerabilities"
                position="right"
                offset={8}
                className="fill-foreground"
                fontSize={12}
              />
            </Bar>
          </BarChart>
        </ChartContainer>
      </CardContent>
      <CardFooter className="p-3 pt-0">
      <div className="overflow-x-auto w-full mx-auto">
        {/* <table className="table-fixed w-full border rounded-lg text-sm shadow-md">
          <thead>
            <tr>
              <th className="px-4 sm:px-14 py-2 text-left font-semibold text-sm" colSpan="1">
                <div className="flex items-center">
                  <ChartLine className="mr-2" />
                  Metrics
                </div>
              </th>
              <th className="px-4 sm:px-14 py-2 text-left font-semibold text-sm" colSpan="1">
                <div className="flex items-center">
                  <ChartLine className="mr-2" />
                  Value
                </div>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="px-4 py-1 border-r ">
                <div className="flex items-center">
                  <List className="mr-2" />
                  Total Count
                </div>
              </td>
              <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.totalCount.toLocaleString()}</td>
            </tr>
            <tr>
              <td className="px-4 py-1 border-r border-gray-300">
                <div className="flex items-center">
                  <UserRoundCheck className="mr-2" />
                  Total Assigned
                </div>
              </td>
              <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.initial.toLocaleString()}</td>
            </tr>
            <tr>
              <td className="px-4 py-1 border-r border-gray-300">
                <div className="flex items-center">
                  <UserRoundX className="mr-2" />
                  Total Unassigned
                </div>
              </td>
              <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.unassigned.toLocaleString()}</td>
            </tr>
            <tr>
              <td className="px-4 py-1 border-r border-gray-300" colSpan="2">
                <table className="table-fixed w-full border border-gray-300 rounded-lg text-sm shadow-md">
                  <thead>
                    <tr>
                      <th className="px-4 sm:px-14 py-2 text-left font-semibold text-sm ">Severity</th>
                      <th className="px-4 sm:px-14 py-2 text-right font-semibold text-sm ">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td className="px-4 py-1">
                        <div className="flex items-center">
                          <CloudAlert className="text-red-500 mr-2" />
                          High Severity
                        </div>
                      </td>
                      <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.scoreRanges["9+"].toLocaleString()}</td>
                    </tr>
                    <tr>
                      <td className="px-4 py-1">
                        <div className="flex items-center">
                          <TriangleAlert className="text-orange-500 mr-2" />
                          Medium Severity
                        </div>
                      </td>
                      <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.scoreRanges["8-9"].toLocaleString()}</td>
                    </tr>
                    <tr>
                      <td className="px-4 py-1">
                        <div className="flex items-center">
                          <Info className="text-yellow-500 mr-2" />
                          Low Severity
                        </div>
                      </td>
                      <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.scoreRanges["7-8"].toLocaleString()}</td>
                    </tr>
                    <tr>
                      <td className="px-4 py-1">
                        <div className="flex items-center">
                          <CheckCircle className="text-green-500 mr-2" />
                          Harmless Severity
                        </div>
                      </td>
                      <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.scoreRanges["1-2"].toLocaleString()}</td>
                    </tr>
                  </tbody>
                </table>
              </td>
            </tr>
          </tbody>
        </table> */}
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
                    {/* <CloudAlert className="text-red-500 mr-2" /> */}
                    High Severity
                  </div>
                </td>
                <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.scoreRanges["9+"].toLocaleString()}</td>
              </tr>
              <tr>
                <td className="px-4 py-1">
                  <div className="flex items-center">
                    {/* <TriangleAlert className="text-orange-500 mr-2" /> */}
                    Medium Severity
                  </div>
                </td>
                <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.scoreRanges["8-9"].toLocaleString()}</td>
              </tr>
              <tr>
                <td className="px-4 py-1">
                  <div className="flex items-center">
                    {/* <Info className="text-yellow-500 mr-2" /> */}
                    Low Severity
                  </div>
                </td>
                <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.scoreRanges["7-8"].toLocaleString()}</td>
              </tr>
              <tr>
                <td className="px-4 py-1">
                  <div className="flex items-center">
                    {/* <CheckCircle className="text-green-500 mr-2" /> */}
                    Harmless Severity
                  </div>
                </td>
                <td className="px-4 sm:px-14 py-1 text-right text-sm font-bold">{stats.scoreRanges["1-2"].toLocaleString()}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      </CardFooter>
    </Card>
  );
}

export default BarGraph;
