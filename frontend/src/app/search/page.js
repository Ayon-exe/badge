"use client";
import Footer from "@/components/Footer";
import Navbar from "@/components/Navbar";
import Search from "@/components/Search";
export default function Page() {
  return (
    <>
      <Navbar />
      <div className=" w-full h-full bg-[url('/background.jpg')] bg-cover bg-center bg-fixed ">
        <div className="text-white justify-start items-center flex flex-col h-full w-full mx-4 md:mx-0 bg-blue-950/30 backdrop-blur-md shadow-lg rounded-lg">
          <div className="flex flex-col items-center justify-center py-10 w-2/3 max:w-4/5">
            <Search/>
          </div>
        </div>
      </div>
      <Footer />
    </>
  );
}