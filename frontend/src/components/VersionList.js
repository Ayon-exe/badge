"use client";

import React, { useState, useMemo } from "react";
import Link from "next/link";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableFooter,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// Utility function to compare version strings
const compareVersions = (a, b) => {
  const partsA = a.split(".").map((part) => {
    const match = part.match(/^\d+/);
    return match ? parseInt(match[0], 10) : 0;
  });
  const partsB = b.split(".").map((part) => {
    const match = part.match(/^\d+/);
    return match ? parseInt(match[0], 10) : 0;
  });

  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const numA = partsA[i] || 0;
    const numB = partsB[i] || 0;
    if (numA !== numB) return numB - numA;
  }
  return 0;
};

// Process data function
const processData = (data) => {
  const versionMap = new Map();

  data.forEach((item) => {
    const version = item.version.trim();
    const range = item.affectedRange.trim();

    if (!versionMap.has(version)) {
      versionMap.set(version, {
        version,
        vulnerabilityCount: item.vulnerabilityCount,
        affectedRanges: new Set(),
      });
    }
    versionMap.get(version).affectedRanges.add(range);
  });

  const processed = Array.from(versionMap.values())
    .map((item) => ({
      ...item,
      affectedRanges: Array.from(item.affectedRanges).sort(),
    }))
    .sort((a, b) => compareVersions(a.version, b.version));

  return processed;
};

export function VersionList({ data, product }) {
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  const { processedData, totalItems } = useMemo(() => {
    const processed = processData(data);
    return {
      processedData: processed,
      totalItems: processed.length,
    };
  }, [data]);

  console.log(data);

  const pageCount = Math.ceil(totalItems / rowsPerPage);
  const startIndex = (currentPage - 1) * rowsPerPage;
  const displayData = processedData.slice(startIndex, startIndex + rowsPerPage);

  const handlePageChange = (newPage) => {
    setCurrentPage(Math.max(1, Math.min(newPage, pageCount)));
  };

  const handleRowsPerPageChange = (value) => {
    setRowsPerPage(Number(value));
    setCurrentPage(1);
  };

  return (
    <div className="w-full space-y-4">
      {/* Top Section: Rows per Page on Left, Pagination on Right */}
      <div className="flex flex-row justify-between items-center w-full mb-4 px-4">
        {/* Rows per Page Dropdown (Left) */}
        <div className="flex flex-row items-center gap-4">
          <span className="text-sm">Rows per page:</span>
          <Select
            value={rowsPerPage.toString()}
            onValueChange={handleRowsPerPageChange}
          >
            <SelectTrigger className="w-[100px]">
              <SelectValue placeholder="Select rows" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="10">10</SelectItem>
                <SelectItem value="20">20</SelectItem>
                <SelectItem value="50">50</SelectItem>
                <SelectItem value="100">100</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>

        {/* Top Right Pagination Buttons */}
        <div className="flex flex-row gap-4">
          <button
            onClick={() => handlePageChange(currentPage - 1)}
            disabled={currentPage === 1}
            className="px-2 w-24 py-1 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
          >
            Previous
          </button>
          <button
            onClick={() => handlePageChange(currentPage + 1)}
            disabled={currentPage === pageCount}
            className="px-2 w-24 py-1 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>

      <Card className="w-full rounded-lg overflow-x-auto">
        <div className="min-w-[600px]">
          <Table>
            <TableCaption>Version Vulnerability Information</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-[150px]">Version</TableHead>
                <TableHead className="min-w-[150px]">Vulnerabilities</TableHead>
                <TableHead className="min-w-[400px]">Affected Ranges</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {displayData.map((item) => (
                <TableRow key={item.version}>
                  <TableCell className="font-medium">{item.version}</TableCell>
                  <TableCell>
                    <Link href={`/product/${product}/version/${encodeURIComponent(item.version)}/vulnerabilities`} className="text-blue-500 hover:underline">
                      {item.vulnerabilityCount}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {item?.affectedRanges?.map((range) => (
                        <span
                          key={`${item.version}-${range}`}
                          className="inline-block px-2 py-1 text-sm rounded"
                        >
                          {range}
                        </span>
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
            <TableFooter>
              <TableRow>
                <TableCell colSpan={3}>
                  <div className="flex items-center justify-between py-2">
                    <span className="text-sm text-gray-500">
                      Showing {startIndex + 1} to {Math.min(startIndex + rowsPerPage, totalItems)} of {totalItems} entries
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handlePageChange(currentPage - 1)}
                        disabled={currentPage === 1}
                        className="px-2 w-24 py-1 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
                      >
                        Previous
                      </button>
                      <span className="px-2">
                        Page {currentPage} of {pageCount}
                      </span>
                      <button
                        onClick={() => handlePageChange(currentPage + 1)}
                        disabled={currentPage === pageCount}
                        className="px-2 w-24 py-1 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                </TableCell>
              </TableRow>
            </TableFooter>
          </Table>
        </div>
      </Card>
    </div>
  );
}

export default VersionList;
