import React from "react";
import Link from "next/link";

function FeedCVEBlock({ data, index }) {
  const formatEPSSScore = (score) => {
    if (!score && score !== 0) return "N/A";
    return (score * 100).toFixed(3).replace(/\.?0+$/, "") + " %";
  };

  const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    try {
      const date = new Date(dateString);
      return date
        .toLocaleDateString("en-GB", {
          month: "2-digit",
          day: "2-digit",
          year: "numeric",
        })
        .replace(/\//g, "/");
    } catch (e) {
      return dateString;
    }
  };

  return (
    <Link href={`/cve/${data.cve_id}`}>
      <div className="w-full min-w-[1000px] min-h-[180px] flex flex-row divide-x divide-gray-600 bg-[#000821] rounded-lg border-[#00B7EF] border-2 border-opacity-50 p-6 justify-between my-4 gap-4">
        <div className="flex flex-col w-3/4">
          <h1 className="text-2xl font-bold text-[#00B7EF]">{data.cve_id}</h1>
          <p className="text-base mt-2 text-gray-200">{data.description}</p>
          <p className="text-sm text-gray-400 mt-2">Source: {data.source}</p>
        </div>

        <div className="flex flex-col justify-between pl-8 w-1/4">
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-400">Max CVSS</span>
            <span
              className={`${
                data.cvss_score === "N/A"
                  ? "bg-[#8A8A8A33] text-white border-gray-700"
                  : data.cvss_score >= 9
                  ? "bg-[#530006] text-[#FF5A65] border-[#530006]"
                  : data.cvss_score >= 7
                  ? "bg-[#855e11] text-[#FDB52A] border-[#855e11]"
                  : data.cvss_score >= 4
                  ? "bg-[#004122] text-[#14CA74] border-[#004122]"
                  : "bg-[#8A8A8A33] text-white border-gray-700"
              } border px-3 py-1 rounded-md text-sm text-center min-w-[60px]`}
            >
              {data?.cvss_score ? data?.cvss_score : "N/A"}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-400">EPSS Score</span>
            <span
              className={`${
                data.epss_score === null
                  ? "bg-[#8A8A8A33] text-white border-gray-700"
                  : data.epss_score * 100 < 0.05
                  ? "bg-[#004122] text-[#14CA74] border-[#004122]"
                  : data.epss_score * 100 >= 0.05 &&
                    data.epss_score * 100 < 0.09
                  ? "bg-[#855e11] text-[#FDB52A] border-[#855e11]"
                  : data.epss_score * 100 >= 0.09
                  ? "bg-[#530006] text-[#FF5A65] border-[#530006]"
                  : "bg-[#8A8A8A33] text-white border-gray-700"
              } border px-3 py-1 rounded-md text-sm text-center min-w-[60px]`}
            >
              {formatEPSSScore(data?.epss_score)}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-400">Published</span>
            <span className="text-sm">{formatDate(data.published_at)}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-400">Updated</span>
            <span className="text-sm">{formatDate(data.updated_at)}</span>
          </div>
        </div>
      </div>
    </Link>
  );
}

export default FeedCVEBlock;
