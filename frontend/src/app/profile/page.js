"use client";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthContext } from "@/components/AuthContext";



export default function Dashboard() {
  const { user, loading, logout } = useAuthContext();
  const [redirectTimer, setRedirectTimer] = useState(3);
  const [totalVendors, setTotalVendors] = useState(<i><Loader2 className="animate-spin" /></i>);
  const [totalProducts, setTotalProducts] = useState(<i><Loader2 className="animate-spin" /></i>);
  const [totalOpenCVEs, setTotalOpenCVEs] = useState(<i><Loader2 className="animate-spin" /></i>);
  const [totalResolvedCVEs, setTotalResolvedCVEs] = useState(<i><Loader2 className="animate-spin" /></i>);
  const [totalIgnoredCVEs, setTotalIgnoredCVEs] = useState(<i><Loader2 className="animate-spin" /></i>);

  
  const router = useRouter(); // Initialize the router

  const navigateToFeed = (tab) => {
    router.push(`/feed?tab=${tab}`);
  };

  useEffect(() => {
    if (!user && !loading) {
      const timer = setInterval(() => {
        setRedirectTimer((prevTimer) => prevTimer - 1);
      }, 1000);
      
      setTimeout(() => {
        clearInterval(timer);
        router.push("/");
      }, 3000);
    }
  }, [loading, user, router]);

  // Add new effect for fetching total vendors
  useEffect(() => {
    if (user && !loading) {
      const fetchTotalVendors = async () => {
        const token = localStorage.getItem('accessToken');
        if (!token) {
          console.log("DEBUG Frontend: No access token found");
          return;
        }
        
        console.log("DEBUG Frontend: Making API request with token:", token.substring(0, 10) + "...");
        
        try {
          const response = await axios.get(`${process.env.SERVER_URL}/api/dashboard/total-vendors`, {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
          
          console.log("DEBUG Frontend: Received response:", response.data);
          setTotalVendors(response.data.totalVendors.toString());
        } catch (err) {
          console.error("DEBUG Frontend: Error fetching total vendors:", err);
          console.log("DEBUG Frontend: Error response data:", err.response?.data);
          setTotalVendors("Error: " + (err.response?.data?.message || err.message));
        }
      };

      fetchTotalVendors();
    }
  }, [user, loading]);

  // Add new effect for fetching total products
  useEffect(() => {
    if (user && !loading) {
      const fetchTotalProducts = async () => {
        const token = localStorage.getItem('accessToken');
        if (!token) return;
        
        try {
          const response = await axios.get(`${process.env.SERVER_URL}/api/dashboard/total-products`, {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
          
          setTotalProducts(response.data.totalProducts.toString());
        } catch (err) {
          console.error("Error fetching total products:", err);
          setTotalProducts("0");
        }
      };
      
      fetchTotalProducts();
    }
  }, [user, loading]);
  
  // Add new effect for fetching total open CVEs
  useEffect(() => {
    if (user && !loading) {
      const fetchTotalOpenCVEs = async () => {
        const token = localStorage.getItem('accessToken');
        if (!token) return;
        
        try {
          const response = await axios.get(`${process.env.SERVER_URL}/api/dashboard/total-open-cves`, {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
          
          setTotalOpenCVEs(response.data.totalOpenCVEs.toString());
        } catch (err) {
          console.error("Error fetching total open CVEs:", err);
          setTotalOpenCVEs("0");
        }
      };
      
      fetchTotalOpenCVEs();
    }
  }, [user, loading]);
  
  // Add new effect for fetching total resolved CVEs
  useEffect(() => {
    if (user && !loading) {
      const fetchTotalResolvedCVEs = async () => {
        const token = localStorage.getItem('accessToken');
        if (!token) return;
        
        try {
          const response = await axios.get(`${process.env.SERVER_URL}/api/dashboard/total-resolved-cves`, {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
          
          setTotalResolvedCVEs(response.data.totalResolvedCVEs.toString());
        } catch (err) {
          console.error("Error fetching total resolved CVEs:", err);
          setTotalResolvedCVEs("0");
        }
      };
      
      fetchTotalResolvedCVEs();
    }
  }, [user, loading]);
  
  // Add new effect for fetching total ignored CVEs
  useEffect(() => {
    if (user && !loading) {
      const fetchTotalIgnoredCVEs = async () => {
        const token = localStorage.getItem('accessToken');
        if (!token) return;
        
        try {
          const response = await axios.get(`${process.env.SERVER_URL}/api/dashboard/total-ignored-cves`, {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
          
          setTotalIgnoredCVEs(response.data.totalIgnoredCVEs.toString());
        } catch (err) {
          console.error("Error fetching total ignored CVEs:", err);
          setTotalIgnoredCVEs("0");
        }
      };
      
      fetchTotalIgnoredCVEs();
    }
  }, [user, loading]);
  
  if (!user && !loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <div className="text-white text-2xl">
          You are not authorized to access this page. Redirecting to{" "}
          <Link href="/" className="text-green">
            Home
          </Link>{" "}
          in {redirectTimer} seconds.
        </div>
      </div>
    );
  }
    
  if (loading) { // Check if user is null and loading is false
    return (
      <div className="flex justify-center items-center h-screen">
        <div className="text-white text-2xl">Loading...</div>
      </div>
    );
  }
  
  return (
    <>
      <Navbar />
      <div className="relative w-full min-h-screen flex justify-center items-center px-16 md:px-0 lg:px-32 xl:px-40">
        <div className="absolute inset-0 bg-[url('/background.jpg')] bg-cover bg-center bg-fixed filter blur-lg -z-10"></div>
        {/* Main Content */}
        <div className="w-[95vw] sm:w-[95vw] md:w-screen lg:w-[80vw] px-2 sm:px-6 md:px-0 lg:px-6 mx-auto bg-blue-950/30 backdrop-blur-md text-white p-2 sm:p-6 md:p-4 lg:p-6 shadow-lg rounded-lg md:rounded-none lg:rounded-lg relative z-10">
          {/* Desktop and Mobile Layout */}
          <div className="flex flex-col lg:flex-row gap-4 lg:gap-2 justify-center items-start py-1 sm:py-2 w-full md:px-2 lg:px-0 md:hidden lg:flex">
            {/* Left column in desktop (Watchlist) */}
            <div className="w-[91vw] sm:w-full lg:w-1/3 flex flex-col order-2 lg:order-1 mt-4 lg:mt-0">
              <WatchlistProvider>
                <Watchlist />
              </WatchlistProvider>
            </div>
            
            {/* Right column in desktop */}
            <div className="w-full lg:w-2/3 flex flex-col gap-3 items-start order-1 lg:order-2">
              <div className="w-full flex flex-wrap justify-between gap-4 sm:gap-6">
                <DashboardBlock
                  className="flex-shrink-0"
                  title1={"Total Vendors"}
                  desc1={totalVendors}
                  info1={"across Watchlists"}
                  title2={"Total Products"}
                  desc2={totalProducts}
                  info2={"across Watchlists"}
                  title3={"Resolved CVE's"}
                  desc3={totalResolvedCVEs}
                  info3={"Resolved"}
                  title4={"Open CVE's"}
                  desc4={totalOpenCVEs}
                  info4={"Require Attention"}
                  title5={"Ignored CVE's"}
                  desc5={totalIgnoredCVEs}
                  info5={"Ignored"}
                  onClickVendor={() => navigateToFeed('')}
                  onClickProduct={() => navigateToFeed('')}
                  onClickResolved={() => navigateToFeed('resolved')}
                  onClickOpen={() => navigateToFeed('open')}
                  onClickIgnored={() => navigateToFeed('ignored')}
                />
              </div>
              <RiskLevel className="mt-4 w-full" />
              <div className="w-full grow">
                <div className="flex flex-col md:flex-row lg:flex-row justify-between gap-4 lg:gap-2 order-3">
                  <div className="w-[91vw] sm:w-full lg:w-3/5">
                    <Card className="w-full h-auto">
                      <RecentCVEsChart />
                    </Card>
                  </div>
                  <div className="w-[91vw] sm:w-full lg:w-2/5 mt-4 md:mt-0 lg:mt-0">
                    <Card className="w-full h-auto">
                      <UnpatchedCVEs />
                    </Card>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          {/* Tablet Layout Only (768px - 1024px) */}
          <div className="hidden md:flex lg:hidden flex-col gap-4 justify-center items-start py-1 sm:py-2 w-full px-6">
            <div className="w-full flex flex-wrap justify-between gap-4 sm:gap-6">
              <DashboardBlock
                className="flex-shrink-0"
                title1={"Total Vendors"}
                desc1={totalVendors}
                info1={"across Watchlists"}
                title2={"Total Products"}
                desc2={totalProducts}
                info2={"across Watchlists"}
                title3={"Resolved CVE's"}
                desc3={totalResolvedCVEs}
                info3={"Resolved"}
                title4={"Open CVE's"}
                desc4={totalOpenCVEs}
                info4={"Require Attention"}
                title5={"Ignored CVE's"}
                desc5={totalIgnoredCVEs}
                info5={"Ignored"}
                onClickVendor={() => navigateToFeed('')}
                onClickProduct={() => navigateToFeed('')}
                onClickResolved={() => navigateToFeed('resolved')}
                onClickOpen={() => navigateToFeed('open')}
                onClickIgnored={() => navigateToFeed('ignored')}
              />
            </div>
            <RiskLevel className="mt-4 w-full" />
            
            {/* Charts section in tablet - full width */}
            <div className="w-full flex flex-row justify-between gap-4">
              <div className="w-1/2">
                <Card className="w-full h-auto">
                  <RecentCVEsChart />
                </Card>
              </div>
              <div className="w-1/2">
                <Card className="w-full h-auto">
                  <UnpatchedCVEs />
                </Card>
              </div>
            </div>
            
            {/* Watchlist in tablet - positioned below charts */}
            <div className="w-full mt-4">
              <WatchlistProvider>
                <Watchlist />
              </WatchlistProvider>
            </div>
          </div>
          
          <div className="flex flex-col md:flex-row lg:flex-row w-full justify-between gap-4 lg:gap-2 mt-4 md:px-2 lg:px-0">
            <div className="w-[91vw] sm:w-full md:w-1/3 lg:w-1/3">
              <Card className="w-full h-auto md:h-[345px] lg:h-[345px]">
                <TopCompaniesChart />
              </Card>
            </div>
            
            <div className="w-[91vw] sm:w-full md:w-2/3 lg:w-2/3 mt-90 md:mt-0 lg:mt-0">
              <Card className="w-full">
                <LiveExploitsTable />
              </Card>
            </div>
          </div>
          
          {/* Top Companies Section */}
          <div className="mt-4 w-[91vw] sm:w-full md:px-2 lg:px-0 mb-10">
            <Card className="w-full">
              <TopCompanies />
            </Card>
          </div>
        </div>
      </div>
      <Footer />
    </>
  );
}