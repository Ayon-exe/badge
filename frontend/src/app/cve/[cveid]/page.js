// Page.js
import CVEBlock from "@/components/CVEBlock";
import Navbar from "@/components/Navbar";
import { getCvebyId } from "@/lib/fetch";
//import { sampleCVEDataWithMetric, sampleCVEDataWithoutMetric } from "@/lib/data";
import Link from "next/link";
import Footer from "@/components/Footer";
import CVSSVectorBreakdown from "@/components/CVSSVectorBreakdown"

export default async function Page({ params }) {
  const { cveid } = await params;

  //uncomment this code for server
  const data = await getCvebyId(cveid);

  // const data = sampleCVEData;
  // till here

  let uniqueArray = [];

  if (data) {
    uniqueArray = data?.cpe?.filter((obj, index, self) =>
      index === self.findIndex((t) => (
        t.vendor === obj.vendor && 
        // t.version === obj.version &&
        t.product === obj.product && 
        t.update === obj.update 
        // t.edition === obj.edition && 
        // t.sw_edition === obj.sw_edition &&
        // t.target_sw === obj.target_sw &&
        // t.target_hw === obj.target_hw 
      ))
    );
  }

  const truncateText = (text, maxLength) => {
    if (text === null || text === undefined) {
      return '';
    }
    if (text.length > maxLength) {
      return text.substring(0, maxLength) + '...';
    }
    return text;
  };

  if (!data) {
    return (
      <div className="bg-[url('/background.jpg')] bg-cover bg-center bg-fixed h-full w-full flex flex-col justify-between">
        <Navbar />
        <div className="blur-container h-full w-full bg-blue-950/30 backdrop-blur-md shadow-lg rounded-lg mx-auto p-4 pt-6 md:p-6 lg:p-6 xl:p-6 ">
          <div className="p-4 md:p-6 lg:p-6 xl:p-6">
            <div className="text-white justify-center items-center flex flex-col my-4 mx-4 md:mx-0">
              <div className="items-start md:w-full lg:w-full xl:w-full mx-auto">
                <h1 className="text-xl font-medium w-full text-center">
                  Vulnerabilities Details: <span className="font-bold">{cveid}</span>
                </h1>
                <p>No data found for CVE ID: {cveid}</p>
              </div>
            </div>
          </div>
        </div>
        <Footer />
      </div>
    );
  }

  return (
    <div className="bg-[url('/background.jpg')] bg-cover bg-center bg-fixed h-full w-full flex flex-col justify-between">
      <Navbar />
      <div className="blur-container h-full w-full bg-blue-950/30 backdrop-blur-md shadow-lg rounded-lg mx-auto">
      <div className="p-4 md:p-6">
          <div className="text-white flex flex-col items-center mx-4 md:mx-0">
            <div className="w-full max-w-7xl">
              <h1 className="text-xl font-medium text-center">
                Vulnerabilities Details: <span className="font-bold">{cveid}</span>
              </h1>
              <CVEBlock data={data} showFullDescription={true} />

              <div className="mt-8">
                <h2 className="text-2xl font-bold text-white text-center">Other Details</h2>
                <div className="flex flex-col justify-center items-center gap-4">
                  <div className="w-full flex flex-wrap md:flex-col lg:flex-row justify-center items-center gap-2 p-4 mt-4 bg-slate-950/75 backdrop-blur-md py-4 rounded-lg border-gray-700 border-2 border-opacity-20">
                    {/* Left Column (Assignee) */}
                    <div className="flex flex-col items-center mr-4 w-full sm:w-1/4">
                      <span className="text-3xl text-blue-400">{data?.assignee ?? "N/A"}</span>
                      <p className="text-sm text-gray-500">Assignee</p>
                    </div>

                    {/* Middle Column (Published Date) */}
                    <div className="flex flex-col items-center w-full sm:w-1/4">
                      <span className="text-3xl text-blue-400">
                        {data?.published_at ? new Date(data.published_at).toLocaleDateString('en-GB') : "N/A"}
                      </span><p className="text-sm text-gray-500">Published</p>
                    </div>

                    {/* Last Column (Last Updated Date) */}
                    <div className="flex flex-col items-center w-full sm:w-1/4">
                      <span className="text-3xl text-blue-400">
                        {data?.updated_at ? new Date(data.updated_at).toLocaleDateString('en-GB') : "N/A"}
                      </span>
                      <p className="text-sm text-gray-500">Last Updated</p>
                    </div>

                    {/* Center Column (Severity)
                    <div className="flex flex-col items-center w-full sm:w-1/5">
                      <span className={`text-3xl ${data?.severity === 'HIGH' ? 'text-red-500' : 'text-yellow-500'}`}>
                        {(data?.severity ?? "N/A").toUpperCase()}
                      </span>
                      <p className="text-sm text-white">Severity</p>
                    </div> */}

                    {/* CVE Links */}
                    {/* bg-[#000B2B] for the old background and bg-slate-950/75 for new background */}
                    <div className="w-full p-0 md:p-4 mt-2 py-4">
                      <h3 className="text-md font-semibold">Links:</h3>
                      <table className="w-full text-sm text-left border-collapse border border-slate-400 rounded-lg">
                        <thead className="bg-[#1A1D23] text-white">
                          <tr>
                            <th className="py-2 px-4 w-8/10 border-b border-r border-slate-400">Url</th>
                            <th className="py-2 px-4 w-2/10 border-b border-slate-400">Type</th>
                          </tr>
                        </thead>
                        <tbody>
                          {data?.patch_url && data.patch_url.map((url, index) => (
                            <tr key={index} className="hover:bg-[#009DBD]">
                              <td className="py-2 px-4">
                                <Link
                                  href={url}
                                  target="_blank"
                                  className="text-green-400 underline hover:text-black break-all"
                                >
                                  {truncateText(url,100)}
                                </Link>
                              </td>
                              <td className="py-2 px-4">
                                <span className="bg-green-600 text-green-200 py-1 px-2 rounded-full text-xs">
                                  Patch
                                </span>
                              </td>
                            </tr>
                          ))}
                          {data?.references && data.references.map((reference, index) => (
                            <tr key={index} className="hover:bg-[#009DBD] hover:text-black hover:hyperlink-black">
                              <td className="py-2 px-4">
                                <Link
                                  href={reference}
                                  target="_blank"
                                  className="text-blue-400 underline hover:text-black break-all"
                                >
                                  {truncateText(reference,100)}
                                </Link>
                              </td>
                              <td className="py-2 px-4">
                                <span className="bg-blue-600 text-blue-200 py-1 px-2 rounded-full text-xs">
                                  Reference
                                </span>
                              </td>
                            </tr>
                          ))}
                          {Array.isArray(data?.vendor_advisory) && data.vendor_advisory.map((vendor_advisory, index) => (
                            <tr key={index} className="hover:bg-[#009DBD] hover:text-black hover:hyperlink-black">
                              <td className="py-2 px-4 max-w-[300px] break-words">
                                <Link
                                  href={vendor_advisory}
                                  target="_blank"
                                  className="text-violet-400 underline hover:text-black break-all"
                                >
                                  {truncateText(vendor_advisory, 100)}
                                </Link>
                              </td>
                              <td className="py-2 px-4">
                                <span className="bg-violet-600 text-violet-200 py-1 px-2 rounded-full text-xs">
                                  Vendor Advisory
                                </span>
                              </td>
                            </tr>
                          ))}

                        </tbody>
                      </table>  
                    </div>

                    {/* CVSS Metrics */}
                      <div className="w-full grid grid-cols-1 lg:grid-cols-3  mt-4 py-4 rounded-lg">
                        {/* Left Column (2/3) */}
                        <div className="col-span-2">
                          <h2 className="text-lg font-bold text-white">CVSS Metrics</h2>
                          {data?.cvss_metrics ? (
                          <div className="flex mt-4 flex-col ">

                            <div className="flex flex-col md:flex-row lg:flex-row xl:flex-row justify-between my-4">
                              <div className="flex flex-col items-center">
                                <span
                                  className={`text-5xl ${data.cvss_score === "N/A"
                                      ? " "
                                      : data.cvss_score < 3
                                        ? "text-green-500 "
                                        : data.cvss_score >= 3 && data.cvss_score < 9
                                          ? "text-yellow-500 "
                                          : data.cvss_score >= 9
                                            ? "text-orange-600 "
                                            : ""
                                    }  px-12 py-1 rounded-md`}
                                >
                                  {data.cvss_score ?? "N/A"}
                                </span>
                                <p className="text-lg">CVSS Score</p>
                              </div>
                              <div className="border-l-4 border-gray-700 h-auto"></div>
                              <div className="flex flex-col items-center">
                                <span
                                  className={`text-5xl ${data.severity === "N/A"
                                      ? ""
                                      : data.severity === "LOW"
                                        ? "text-green-500"  // Green for Low
                                        : data.severity === "MEDIUM"
                                          ? "text-orange-500"
                                          : data.severity === "HIGH"
                                            ? "text-red-600"
                                            : data.severity === "CRITICAL"
                                              ? "text-red-800"
                                              : ""
                                    } px-12 py-1 rounded-md`}
                                >
                                  {(data.severity ?? "N/A").toUpperCase()}
                                </span>
                                <p className="text-lg ">CVSS Base Severity</p>
                              </div>
                              <div className="border-l-4 border-gray-700 h-auto"></div>
                              <div className="flex flex-col items-center">
                                <span
                                  className={`text-5xl text-blue-500 ${data.cvss_metrics?.version === "N/A"
                                      ? ""
                                      : ""
                                    }  px-12 py-1 rounded-md`}
                                >
                                  {data.cvss_metrics?.version ?? "N/A"}
                                </span>
                                <p className="text-lg">Version</p>
                              </div>
                            </div>

                            <br />

                            <div>
                              <CVSSVectorBreakdown cvssMetrics={data.cvss_metrics} />
                            </div>
                          </div>
                        ) : (
                      <div className="flex mt-4 flex-col">
                        <p className="text-3xl text-gray-500">CVSS metrics are not available.</p>
                      </div>
                    ) }
                       </div>
                        
                        {/* Right Column (1/3) */}
                        <div className="col-span-1 ml-0 md:ml-4 pt-10">
                            <div>
                              <h3 className="text-md font-semibold text-blue-300">Vulnerable Products:</h3>
                              <div className="overflow-y-auto max-h-70 overflow-x-hidden scrollbar">
                                <table className="w-full bg-blue-900/20 backdrop-blur-md rounded-2xl">
                                  <thead className="bg-blue-800/20 text-blue-200 rounded-t-2xl">
                                    <tr>
                                      <th className="py-2 px-2 w-3/10 border-b border-blue-500/50">Vendor</th>
                                      <th className="py-2 px-2 w-2/5 border-b border-blue-500/50">Product</th>
                                      <th className="py-2 px-2 w-3/10 border-b border-blue-500/50">Version</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {uniqueArray.map((c, index) => (
                                      <tr key={index} className="hover:bg-blue-700/20">
                                        <td className="py-2 px-2 border-b text-blue-200">
                                          <Link
                                            href={`/vendor/${c?.vendor}`}
                                            className="text-blue-200 hover:underline"
                                          >
                                            {c?.vendor.replace(/_/g, " ")}
                                          </Link>
                                        </td>
                                        <td className="py-2 px-2 border-b text-blue-200">
                                          <Link
                                            href={`/product/${c?.product?.replaceAll(/\s+/g, "-")}`}
                                            className="text-blue-200 hover:underline"
                                          >
                                            {c?.product?.replace(/_/g, " ")}
                                          </Link>
                                        </td>
                                        <td className="py-2 px-2 border-b">
                                        <span className="text-pink-500">
                                            {c?.versions?.version === "*" ? "*" : c?.versions?.version ?? "N/A"}
                                        </span>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>

                              {/* Weaknesses */}
                              <br />
                              <h3 className="text-md font-semibold text-blue-300">Weaknesses:</h3>

                              <div className="overflow-y-auto max-h-50 scrollbar">
                                <table className="min-w-full bg-blue-900/20 backdrop-blur-md rounded-2xl">
                                  <thead className="bg-blue-800/20 text-blue-200 rounded-t-2xl">
                                    <tr>
                                      <th className="py-2 px-4 w-4/10 border-b border-blue-500/50">CWE-Id</th>
                                      <th className="py-2 px-4 w-6/10 border-b border-blue-500/50">Description</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {data.weaknesses.map((weaknesses, index) => (
                                      <tr key={index} className="hover:bg-blue-700/20">
                                        <td className="py-2 px-4 border-b text-blue-200">
                                          {weaknesses.cwe_id}
                                        </td>
                                        <td className="py-2 px-4 border-b text-blue-200">
                                          {truncateText(weaknesses.description, 30)}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                        </div>
                      </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}