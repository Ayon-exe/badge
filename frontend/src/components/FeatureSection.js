import React from "react";
import Image from "next/image";
import featureImage from "@/assets/featureImage.webp";

export default function FeatureSection() {
  return (
    <div className="flex flex-col md:flex-row justify-around items-center py-4 w-full md:w-2/3 bg-slate-950/75 backdrop-blur-md rounded-lg border-[#343B4F] border-2 ">
      <div className="mx-8">
        <h1 className="text-xl font-bold my-4">
          Autonomous penetration testing out of the box
        </h1>
        <ul className="list-disc ml-8 text-gray-300">
          <li>
            <b className="text-white">Self Configuring:</b> No setup,
            configuration, or scheduling is required, <br />
            Hadrian's AI platform is 100% autonomous
          </li>
          <li>
            <b className="text-white">Self Configuring:</b> No setup,
            configuration, or scheduling is required, <br />
            Hadrian's AI platform is 100% autonomous
          </li>
          <li>
            <b className="text-white">Self Configuring:</b> No setup,
            configuration, or scheduling is required, <br />
            Hadrian's AI platform is 100% autonomous
          </li>
        </ul>
      </div>
      <div className="m-6">
        <Image src={featureImage} width={300} alt="Feature Image" />
      </div>
    </div>
  );
}
