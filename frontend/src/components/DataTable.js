import {
  Table,
  TableBody,
  TableCell,
  TableFooter,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent } from "@/components/ui/card";
import {ChevronLeft, ChevronRight } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import Link from "next/link";

export function DataTable({ data, columns, type, pagination, rowLimit }) {

  const truncateText = (text, maxLength) => {
    if (text.length <= maxLength) {
      return text;
    }
    return text.substring(0, maxLength) + '...';
  };

  return (
    <Card className="w-full bg-slate-950/75 backdrop-blur-md shadow-lg rounded-lg text-lg mx-auto">
      <CardContent>
        <div className="flex flex-col md:flex-row justify-between items-center my-4 p-2 sm:p-4">
          <div className="flex flex-row items-center gap-2 sm:gap-4 w-fit text-nowrap mb-4 ">
            <span className="sm:hidden"> Rows: </span>
            <span className="sm:block hidden "> Rows per page: </span>
            <Select value={rowLimit.value} onValueChange={rowLimit.onChange}>
              <SelectTrigger className="w-16 sm:w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {rowLimit.options.map((option) => (
                    <SelectItem key={option} value={option}>
                      {option}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-row gap-5 items-center text-lg justify-center">
            <button
              className="ml-2 px-2 w-1/4 sm:w-24 py-1 bg-blue-500 text-white rounded disabled:opacity-50 hover:bg-blue-600"
              disabled={pagination.currentPage === 1}
              onClick={() =>
                pagination.onPageChange(pagination.currentPage - 1)
              }
            >
              <span className="sm:hidden"><ChevronLeft/></span>
             <span className="hidden sm:block">Previous</span>

            </button>
            Page {pagination.currentPage} of {pagination.totalPages}
            <button
              className="mr-2 px-2 w-1/4 sm:w-24 py-1 bg-blue-500 text-white rounded disabled:opacity-50 hover:bg-blue-600"
              disabled={pagination.currentPage === pagination.totalPages}
              onClick={() =>
                pagination.onPageChange(pagination.currentPage + 1)
              }
            >
              <span className="sm:hidden"><ChevronRight/></span>
             <span className="hidden sm:block">Next</span>
            </button>
          </div>
        </div>
        <div className="h-175 overflow-y-auto scrollbar">
        <Table className="table-fixed">
          {/* Header Row - No Borders & Forced White Text */}
          <TableHeader>
            <TableRow className="bg-[#00B3F3] text-white text-opacity-100 !important border-none">
              {columns.map((column) => (
                <TableHead
                  key={column.id}
                  className={`text-s sm:text-xs text-center p-3 font-semibold uppercase tracking-wider border-none text-white text-opacity-100 
                    ${column.width} 
                    ${column.id === 'sr' ? "hidden md:block" : " "} 
                    ${column.id === 'lastUpdated' ? "hidden md:block" : " "}`}
                >
                  {column.id === "vulnerabilities" ? "CVE's" : column.colname}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody className="text-center text-lg">
            {data.map((row, index) => (
              <TableRow key={index}>
                {columns.map((column) => (
                  <TableCell key={column.id} className={`${column.id === 'sr' ? "hidden md:block" : " "} ${column.id === 'lastUpdated' ? "hidden md:block" : " "} word-break: break-all; ${column.width}`}>
                    {column.id === type ? (
                      <Link
                        href={`/${type}/${encodeURIComponent(row[column.id])}`}
                        className="underline"
                      >
                        {truncateText(row[column.id], 25)}{" "}
                      </Link>
                    ) : (
                      row[column.id]
                    )}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
        </div>
            <div className="flex flex-row gap-5 items-center text-lg w-full justify-center mt-4">
              <button
                className="mr-2 px-2 w-24 py-1 bg-blue-500 text-white rounded disabled:opacity-50 hover:bg-blue-600"
                disabled={pagination.currentPage === 1}
                onClick={() =>
                  pagination.onPageChange(pagination.currentPage - 1)
                }
              >
              <span className="sm:hidden"><ChevronLeft/></span>
             <span className="hidden sm:block">Previous</span>
              </button>
              Page {pagination.currentPage} of {pagination.totalPages}
              <button
                className="ml-2 px-2 w-24 py-1 bg-blue-500 text-white rounded disabled:opacity-50 hover:bg-blue-600"
                disabled={pagination.currentPage === pagination.totalPages}
                onClick={() =>
                  pagination.onPageChange(pagination.currentPage + 1)
                }
              >
              <span className="sm:hidden"><ChevronRight/></span>
             <span className="hidden sm:block">Next</span>
              </button>
            </div>
      </CardContent>
    </Card>
  );
}