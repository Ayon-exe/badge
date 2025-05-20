"use client";

import Footer from "@/components/Footer";
import Navbar from "@/components/Navbar";
import Link from "next/link";
import Feed1 from "@/components/watchlist/Feed1";
import { useEffect, Suspense, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthContext } from "@/components/AuthContext";

export default function Page() {
  const { user, loading, logout } = useAuthContext();
  const [redirectTimer, setRedirectTimer] = useState(3);
  const router = useRouter();

  useEffect(() => {
  //  if (!user && !loading) {
      const timer = setInterval(() => {
        setRedirectTimer((prevTimer) => prevTimer - 1);
      }, 1000);

      setTimeout(() => {
        clearInterval(timer);
        router.push("/");
      }, 3000);
  // }
  }, [loading, user, router]);

  useEffect(() => {
    // More robust reset handling
    const handlePageLoad = () => {
      // Clear feed state from session storage directly in page component
      if (typeof window !== "undefined") {
        sessionStorage.removeItem("feed_state");

        // Dispatch event with all default values
        const resetEvent = new CustomEvent("feedReset", {
          detail: {
            page: 1,
            limit: 10,
            selectedFilters: [],
            activeWatchlistIndex: 0,
          },
        });

        window.dispatchEvent(resetEvent);
        console.log("Feed page loaded - reset event dispatched");
      }
    };

    // Only run on first render
    handlePageLoad();
  }, []);

  //to be uncommented later
  // if (!user && !loading) {
  //   return (
  //     <>
  //       <div className="flex justify-center items-center h-screen">
  //         <div className="text-white text-2xl">
  //           You are not authorized to access this page. Redirecting to{" "}
  //           <Link href="/" className="text-green">
  //             Home
  //           </Link>{" "}
  //           in {redirectTimer} seconds.
  //         </div>
  //       </div>
  //     </>
  //   );
  // }

  if (loading) {
    return (
      <>
        <div className="flex justify-center items-center h-screen">
          <div className="text-white text-2xl">loading...</div>
        </div>
      </>
    );
  }

  return (
    <>
        <div className="flex justify-center items-center h-screen">
          <div className="text-white text-2xl">
    404 Not Found. Redirecting to{" "}
            <Link href="/" className="text-green">
              Home
            </Link>{" "}
    {/* in {redirectTimer} seconds. */}
          </div>
        </div>
    {/*
      <Navbar />
      <div className=" w-full h-full bg-[url('/background.jpg')] bg-cover bg-center bg-fixed ">
        <div className="text-white justify-start items-center flex flex-col h-full w-full py-4 mx-4 md:mx-0 bg-blue-950/30 backdrop-blur-md shadow-lg rounded-lg">
          <div className="flex items-center justify-center w-2/3">
            {/* <WatchlistPopup /> * /}
          </div>
          <div className="flex flex-1 w-full items-center justify-center py-2">
            {/* Wrap Feed component with Suspense to fix the error * /}
            <Suspense
              fallback={
                <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-500"></div>
              }
            >
              <Feed1 />
            </Suspense>
          </div>
        </div>
      </div>
      <Footer />
      */}
    </>
  );
}
