"use client";

import { Newspaper, Loader2 } from "lucide-react";
import { LabelList, Legend, RadialBar, RadialBarChart, ResponsiveContainer } from "recharts";
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

const chartConfig = {
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
};

export function RadialGraph4() {
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch(`${process.env.SERVER_URL}/api/cve/stats`);
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        const jsonData = await response.json();
        setData(jsonData);
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
      <Card className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm">
        <CardContent className="flex items-center justify-center min-h-[300px]">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm">
        <CardContent className="flex items-center justify-center min-h-[300px] text-destructive">
          Error loading data: {error}
        </CardContent>
      </Card>
    );
  }

  const chartData = [
    {
      name: "24 Hours",
      value: data?.exploitedStats?.sinceYesterday || 20,
      fill: "#e60b51",
    },
    {
      name: "7 Days",
      value: data?.exploitedStats?.last7Days || 50,
      fill: "#e6be0b",
    },
    {
      name: "30 Days",
      value: data?.exploitedStats?.last30Days || 100,
      fill: "#0be63e",
    },
  ];

  // const style = {
  //   top: '50%',
  //   right: 0,
  //   transform: 'translate(0, 200%)',
  //   lineHeight: '24px',
  // };

  const style = {
    top: '50%',
    right: 0,
    transform: 'translate(25%, -50%)',
    lineHeight: '24px',
  };

  return (
    <Card className="h-full w-full flex flex-col rounded-lg bg-slate-950/75 backdrop-blur-sm">
      <CardHeader className="pb-0">
        <CardDescription className="flex flex-row text-[#00CBF0] text-sm font-semibold">
          <Newspaper className="mr-2" size={18} />
          Published CVE's Over time
        </CardDescription>
      </CardHeader>
      <CardContent className="flex-1 pb-0">
        <ChartContainer
          config={chartConfig}
          className="mx-auto min-h-[120px] ml-[-70px] h-full w-full"
        >
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            data={chartData}

            startAngle={0}
            endAngle={360}
            innerRadius="30%"
            outerRadius="100%"
            barSize={20}
          >
            <ChartTooltip
              cursor={false}
              content={
                <ChartTooltipContent
                  hideLabel
                  nameKey="name"
                  valueKey="value"
                />
              }
            />
            <RadialBar dataKey="value" background max={100} cornerRadius={30}>
              {/* <LabelList
                dataKey="name"
                position="insideStart"
                fill="#fff"
                fontSize={12}
              /> */}
            </RadialBar>
            <Legend iconSize={10} layout="vertical" verticalAlign="middle" wrapperStyle={style} />
          </RadialBarChart>
        </ResponsiveContainer>
        </ChartContainer>
      </CardContent>
      {/* <CardFooter className="flex flex-col items-start gap-2">
        <div className="text-md font-medium">Statistics:</div>
        <div className="grid grid-cols-3 gap-4 text-md">
          <div>
            <div className="font-medium">24 Hours</div>
            <div>{data?.newAndUpdatedCVEs?.updatedSinceYesterday}</div>
          </div>
          <div>
            <div className="font-medium">7 Days</div>
            <div>{data?.newAndUpdatedCVEs?.updatedLast7Days}</div>
          </div>
          <div>
            <div className="font-medium">30 Days</div>
            <div>{data?.newAndUpdatedCVEs?.updatedLast30Days}</div>
          </div>
        </div>
      </CardFooter> */}
    </Card>
  );
}

export default RadialGraph4;
