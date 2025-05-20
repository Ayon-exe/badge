import React from "react";
import Link from "next/link";

function CVEProduct({ data }) {
  if (!data || !data.cve_id) {
    return null;
  }

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

  return (
    <Link href={`/cve/${data.cve_id}`}>
      <div className="w-full flex flex-col md:flex-row divide-y md:divide-y-0 md:divide-x divide-gray-600 bg-[#000821] rounded-lg border-[#00B7EF] border-2 border-opacity-50 p-4 justify-between my-4">
        <div className="flex flex-col w-full md:w-2/3 pr-0 md:pr-4 pb-4 md:pb-0">
          <h1 className="text-2xl font-bold mt-1 text-[#00B7EF]">{data.cve_id}</h1>
          <p className="text-sm mt-2 flex-1">{data.description}</p>
          <p className="text-sm text-gray-400">Source: {data.source}</p>
        </div>
        <div className="flex flex-col justify-between w-full md:w-1/3 md:pl-4 pt-4 md:pt-0">
          <div className="flex justify-between space-x-4">
            <span className="text-sm text-gray-400">Max CVSS</span>
            <span
              className={`${
                data.cvss_score === 'N/A' 
                  ? 'bg-[#8A8A8A33] text-white border-gray-700'
                  : parseFloat(data.cvss_score) < 5
                  ? 'bg-[#004122] text-[#14CA74] border-[#004122]'
                  : parseFloat(data.cvss_score) <= 7
                  ? 'bg-[#855e11] text-[#FDB52A] border-[#855e11]'
                  : 'bg-[#530006] text-[#FF5A65] border-[#530006]'
              } border px-2 py-1 rounded-md text-sm`}
            >
              {data.cvss_score ? data.cvss_score : 'N/A'}
            </span>
          </div>
          <div className="flex justify-between space-x-4 mt-2">
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
          <div className="flex justify-between space-x-4 mt-2">
            <span className="text-sm text-gray-400">Published</span>
            <span className="text-sm">{formatDate(data.published_at)}</span>
          </div>
          <div className="flex justify-between space-x-4 mt-2">
            <span className="text-sm text-gray-400">Updated</span>
            <span className="text-sm">{formatDate(data.updated_at)}</span>
          </div>
        </div>
      </div>
    </Link>
  );
}

export default CVEProduct;
