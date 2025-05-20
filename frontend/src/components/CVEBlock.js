import React from "react";
import Link from "next/link";

function CVEBlock({ data }) {
  const formatEPSSScore = (score) => {
    if (!score && score !== 0) return 'N/A';
    return (score * 100).toFixed(3).replace(/\.?0+$/, '') + ' %';
  };

  const formatDate = (dateString, options = {}) => {
    if (!dateString) return 'N/A';
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString(options.locale || 'en-GB', {
        month: '2-digit',
        day: '2-digit',
        year: 'numeric',
        ...options,
      });
    } catch (e) {
      return dateString;
    }
  };

  const truncateText = (text, maxLength) => {
    if (text.length > maxLength) {
      return text.substring(0, maxLength) + '...';
    }
    return text;
  };

  return (
    <Link href={`/cve/${data.cve_id}`}>
<div className="w-full flex flex-col md:flex-row divide-y md:divide-y-0 md:divide-x divide-gray-600 bg-slate-950/75 backdrop-blur-md rounded-lg border-2 border-gray-600 border-opacity-50 p-4 justify-between my-4 gap-4 hover:border-[#00CBF0]">
        
        <div className="flex flex-col w-full">
          <h1 className="text-2xl md:text-3xl font-bold text-[#00B7EF]">{data.cve_id}</h1>
          <p className="text-base mt-2 text-gray-200">{truncateText(data.description, 200)}</p>
        </div>

        <div className="flex flex-col justify-between pl-4 w-full md:w-1/4 space-y-2 mt-4 md:mt-0">
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-400">Max CVSS</span>
            <span
              className={`${
                data.cvss_score === 'N/A' 
                ? "bg-[#8A8A8A33] text-white border-gray-700"
                : data.cvss_score < 3
                ? "bg-[#004122] text-[#14CA74] border-[#004122]"
                : data.cvss_score >= 3 && data.cvss_score < 9
                ? "bg-[#855e11] text-[#FDB52A] border-[#855e11]"
                : data.cvss_score >= 9
                ? "bg-[#530006] text-[#FF5A65] border-[#530006]"
                : "bg-[#8A8A8A33] text-white border-gray-700"
              } border px-3 py-1 rounded-md text-sm text-center min-w-[60px]`}
            >
              {data?.cvss_score ? data?.cvss_score : 'N/A'}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-sm text-gray-400">EPSS Score</span>
            <span className={`${
              data.epss?.epss_score === null 
              ? "bg-[#8A8A8A33] text-white border-gray-700"
              : (data.epss?.epss_score * 100) < 0.05
              ? "bg-[#004122] text-[#14CA74] border-[#004122]"
              : (data.epss?.epss_score * 100) >= 0.05 && (data.epss?.epss_score * 100) < 0.09 
              ? "bg-[#855e11] text-[#FDB52A] border-[#855e11]"
              : (data.epss?.epss_score * 100) >= 0.09 
              ? "bg-[#530006] text-[#FF5A65] border-[#530006]"
              : "bg-[#8A8A8A33] text-white border-gray-700"
            } border px-3 py-1 rounded-md text-sm text-center min-w-[60px]`}>
              {formatEPSSScore(data.epss?.epss_score)}
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

export default CVEBlock;
