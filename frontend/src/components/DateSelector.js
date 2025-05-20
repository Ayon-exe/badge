"use client"
import {React, useState } from "react";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export function DateSelector({ selectedDate, onChange }) {
  const [year, month] = selectedDate.split("-");
  const [selectedYear, setSelectedYear] = useState(year);

  // const yearOptions = [
  //   { value: "all", label: "All Years" },
  //   { value: "2025", label: "2025" },
  //   { value: "2024", label: "2024" },
  //   { value: "2023", label: "2023" },
  //   { value: "2022", label: "2022" },
  //   { value: "2021", label: "2021" },
  //   { value: "2020", label: "2020" },
  //   { value: "2019", label: "2019" },
  //   { value: "2018", label: "2018" },
  //   { value: "2017", label: "2017" },
  //   { value: "2016", label: "2016" },
  //   { value: "2015", label: "2015" },
  //   { value: "2014", label: "2014" },
  // ];

  const currentYear = new Date().getFullYear();
  const yearOptions = [];

  for (let year = currentYear; year >= 2014; year--) {
    yearOptions.push({ value: year.toString(), label: year.toString() });
  }

yearOptions.unshift({ value: "all", label: "All Years" });

  const monthOptions = [
    { value: "all", label: "All Months" },
    { value: "01", label: "January" },
    { value: "02", label: "Febuary" },
    { value: "03", label: "March" },
    { value: "04", label: "April" },
    { value: "05", label: "May" },
    { value: "06", label: "June" },
    { value: "07", label: "July" },
    { value: "08", label: "August" },
    { value: "09", label: "September" },
    { value: "10", label: "October" },
    { value: "11", label: "November" },
    { value: "12", label: "December" },
  ];

  const getNextYearOption = () => {
    const nextYearIndex = yearOptions.findIndex((option) => option.value === year) + 1;
    return yearOptions[nextYearIndex].value;
  };

  const handleYearChange = (newYear) => {
    setSelectedYear(newYear);
    onChange(`${newYear}-${month}`);
  };

  const handleMonthChange = (newMonth) => {
    console.log('handleMonthChange called with newMonth:', newMonth);
    if (newMonth === "all") {
      onChange(`${year}-all`);
    } else {
      if (year === "all") {
        const firstYear = yearOptions[1].value; // get the first year option (index 1)
        handleYearChange(firstYear); // update the year selection
      }
      onChange(`${year}-${newMonth}`);
    }
  };

  return (
    <div className="flex space-x-4">
      <Select value={selectedYear} onValueChange={handleYearChange}>
        <SelectTrigger className="w-[130px]">
          <SelectValue placeholder="Select Year" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            {yearOptions.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
      <Select defaultValue={month} onValueChange={handleMonthChange}>
        <SelectTrigger className="w-[130px]">
          <SelectValue placeholder="Select Month" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            {monthOptions.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
    </div>
  );
}