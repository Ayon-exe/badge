"use client";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import React, { useEffect, useRef } from "react";

const badges = [
  {
    id: 1,
    title: "Cyber Defender",
    img: "/images/img1.png",
    description:
      "Awarded for demonstrating exceptional skills in protecting digital infrastructure against cyber threats and attacks.",
  },
  {
    id: 2,
    title: "Network Sentinel",
    img: "/images/img2.png",
    description:
      "Recognizes expertise in monitoring and defending enterprise networks.",
  },
  {
    id: 3,
    title: "Malware Hunter",
    img: "/images/img3.png",
    description:
      "Given to individuals who identify and neutralize malware threats effectively.",
  },
  {
    id: 4,
    title: "Encryption Expert",
    img: "/images/img4.png",
    description:
      "Honors deep understanding and implementation of encryption protocols.",
  },
  {
    id: 5,
    title: "Encryption Expert",
    img: "/images/img5.png",
    description:
      "Honors deep understanding and implementation of encryption protocols.",
  },
  {
    id: 6,
    title: "Encryption Expert",
    img: "/images/img6.png",
    description:
      "Honors deep understanding and implementation of encryption protocols.",
  },
  {
    id: 7,
    title: "Encryption Expert",
    img: "/images/img7.png",
    description:
      "Honors deep understanding and implementation of encryption protocols.",
  },
  {
    id: 8,
    title: "Encryption Expert",
    img: "/images/img8.png",
    description:
      "Honors deep understanding and implementation of encryption protocols.",
  },
];

export default function LandingPage() {
  const [activeIndex, setActiveIndex] = React.useState(0);
  const carouselRef = useRef(null);

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveIndex((prev) => (prev + 1) % badges.length);
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const selectBadge = (i) => setActiveIndex(i);

  return (
    <>
      <Navbar />
      <div className="min-h-screen overflow-x-hidden bg-gradient-to-br from-primary-dark to-primary-medium text-text-light font-sans">
        <div className="max-w-[1200px] mx-auto px-5">
          {/* Hero */}
          <section className="min-h-[calc(100vh-70px)] flex items-center justify-center text-center px-5 py-12 relative">
            <div className="max-w-[800px] animate-fadeIn">
              <img
                src="https://static.wixstatic.com/media/e48a18_c949f6282e6a4c8e9568f40916a0c704~mv2.png/v1/crop/x_0,y_151,w_1920,h_746/fill/w_203,h_79,fp_0.50_0.50,q_85,usm_0.66_1.00_0.01,enc_auto/For%20Dark%20Theme.png"
                alt="Logo"
                className="max-w-[200px] mb-5 drop-shadow-[0_0_20px_rgba(0,212,255,0.5)] mx-auto"
              />
              <h1 className="text-3xl sm:text-4xl font-extrabold leading-tight mb-5">
                Cybersecurity Badges
              </h1>
              <p className="text-lg sm:text-xl max-w-[600px] mx-auto mb-10 text-text-medium">
                Earn and showcase badges for your cybersecurity skills and achievements.
              </p>
              <div className="flex justify-center gap-5 flex-wrap">
                <button className="px-7 py-3 text-base sm:text-lg border border-cyan-400 bg-gradient-to-br from-cyan-300/20 to-cyan-400/20 hover:from-cyan-300/40 hover:to-cyan-400/40 hover:shadow-[0_0_20px_rgba(0,212,255,0.5)] transition rounded">
                  Get Started
                </button>
                <button className="px-7 py-3 text-base sm:text-lg border border-white/20 bg-white/10 hover:bg-white/20 transition rounded">
                  Learn More
                </button>
              </div>
            </div>
          </section>

          {/* Featured Badge */}
          <section className="py-20">
            <h2 className="text-3xl sm:text-4xl mb-10 text-center">Featured Badge</h2>
            <div className="flex items-center gap-10 flex-wrap md:flex-nowrap text-text-light">
              <div className="flex-1 text-center md:text-left">
                <h3 className="text-xl sm:text-2xl mb-5 font-semibold">
                  {badges[activeIndex].title}
                </h3>
                <p className="text-text-medium text-base sm:text-lg leading-relaxed mb-8 max-w-lg mx-auto md:mx-0">
                  {badges[activeIndex].description}
                </p>
                <div className="flex gap-8 flex-wrap justify-center md:justify-start">
                  <div className="bg-white/5 rounded-lg p-4 text-center flex-1 min-w-[150px]">
                    <p className="text-xl font-bold text-cyan-400 mb-1">150+</p>
                    <p className="text-sm text-text-medium">Holders</p>
                  </div>
                  <div className="bg-white/5 rounded-lg p-4 text-center flex-1 min-w-[150px]">
                    <p className="text-xl font-bold text-cyan-400 mb-1">2024</p>
                    <p className="text-sm text-text-medium">Year Launched</p>
                  </div>
                </div>
              </div>
              <div className="w-[250px] h-[250px] rounded-full bg-gradient-radial from-cyan-400/10 to-transparent flex items-center justify-center mx-auto md:mx-0">
                <img
                  src={badges[activeIndex].img}
                  alt={badges[activeIndex].title}
                  className="max-w-[80%] max-h-[80%] object-contain drop-shadow-md animate-float"
                />
              </div>
            </div>
          </section>

          {/* Badge Carousel */}
          <section className="py-20 bg-gradient-to-t from-primary-dark to-transparent">
            <h2 className="text-3xl sm:text-4xl mb-10 text-center">All Badges</h2>
            <div className="overflow-x-auto no-scrollbar px-5">
              <div
                className="flex gap-6 justify-start scroll-smooth snap-x snap-mandatory"
                ref={carouselRef}
              >
                {badges.map((badge, i) => (
                  <div
                    key={badge.id}
                    onClick={() => selectBadge(i)}
                    className={`w-24 h-24 flex-shrink-0 snap-center cursor-pointer rounded-lg flex items-center justify-center transition transform ${
                      i === activeIndex
                        ? "bg-cyan-400/20 shadow-lg scale-110"
                        : "bg-white/5 hover:bg-white/10 hover:-translate-y-1"
                    }`}
                  >
                    <img
                      src={badge.img}
                      alt={badge.title}
                      className="max-w-[80%] max-h-[80%] object-contain"
                    />
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* Why Earn Badges */}
          <section className="py-20">
            <h2 className="text-3xl sm:text-4xl text-center text-white mb-10">
              Why Earn Badges?
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
              {[
                { emoji: "🏆", title: "Showcase Skills", text: "Display your verified cybersecurity skills and knowledge to employers and peers." },
                { emoji: "🚀", title: "Career Growth", text: "Advance your career by earning increasingly advanced badges in your field." },
                { emoji: "🔍", title: "Validate Expertise", text: "Prove your capabilities through practical challenges and assessments." },
                { emoji: "🌐", title: "Join Community", text: "Connect with other cybersecurity professionals in a growing community." },
              ].map((item, index) => (
                <div key={index} className="p-8 flex flex-col items-center text-center transition-transform duration-300 hover:-translate-y-2 hover:shadow-xl bg-white/5 rounded-lg">
                  <div className="text-5xl mb-5 bg-gradient-to-br from-cyan-400 to-teal-400 bg-clip-text text-transparent">
                    {item.emoji}
                  </div>
                  <h3 className="text-lg sm:text-xl text-white mb-3 font-semibold">
                    {item.title}
                  </h3>
                  <p className="text-sm sm:text-base text-gray-300 leading-relaxed">
                    {item.text}
                  </p>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
      <Footer />
    </>
  );
}