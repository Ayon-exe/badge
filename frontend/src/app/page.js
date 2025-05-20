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

const features = [
  {
    id: 1,
    title: "Fast Performance",
    description: "Our platform delivers lightning fast speeds for all users.",
    icon: (
      <img
        src="/images/img1.png"
        alt="Fast Performance"
        className="w-12 h-12 inline"
      />
    ),
  },
  {
    id: 2,
    title: "Secure",
    description: "Top-notch security measures keep your data safe and sound.",
    icon: (
      <img
        src="/images/img2.png"
        alt="Secure"
        className="w-12 h-12 inline"
      />
    ),
  },
  {
    id: 3,
    title: "User Friendly",
    description: "Designed with simplicity and ease of use in mind.",
    icon: (
      <img
        src="/images/img3.png"
        alt="User Friendly"
        className="w-12 h-12 inline"
      />
    ),
  },
  {
    id: 4,
    title: "User Friendly",
    description: "Designed with simplicity and ease of use in mind.",
    icon: (
      <img
        src="/images/img4.png"
        alt="User Friendly"
        className="w-12 h-12 inline"
      />
    ),
  },
  {
    id: 5,
    title: "User Friendly",
    description: "Designed with simplicity and ease of use in mind.",
    icon: (
      <img
        src="/images/img5.png"
        alt="User Friendly"
        className="w-12 h-12 inline"
      />
    ),
  },
  {
    id: 6,
    title: "User Friendly",
    description: "Designed with simplicity and ease of use in mind.",
    icon: (
      <img
        src="/images/img6.png"
        alt="User Friendly"
        className="w-12 h-12 inline"
      />
    ),
  },
  {
    id: 7,
    title: "User Friendly",
    description: "Designed with simplicity and ease of use in mind.",
    icon: (
      <img
        src="/images/img7.png"
        alt="User Friendly"
        className="w-12 h-12 inline"
      />
    ),
  },
  {
    id: 8,
    title: "User Friendly",
    description: "Designed with simplicity and ease of use in mind.",
    icon: (
      <img
        src="/images/img8.png"
        alt="User Friendly"
        className="w-12 h-12 inline"
      />
    ),
  },
];

export default function LandingPage() {
  const [activeIndex, setActiveIndex] = React.useState(0);
  const carouselRef = useRef(null);

  // Auto-cycle every 5 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setActiveIndex((prev) => (prev + 1) % badges.length);
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  // Scroll into view on index change
  // useEffect(() => {
  //   if (carouselRef.current) {
  //     const el = carouselRef.current.children[activeIndex];
  //     el?.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
  //   }
  // }, [activeIndex]);

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
              <h1 className="text-[3.5rem] font-extrabold leading-[1.2] mb-5">
                Cybersecurity Badges
              </h1>
              <p className="text-[1.2rem] max-w-[600px] mx-auto mb-10 text-text-medium">
                Earn and showcase badges for your cybersecurity skills and achievements.
              </p>
              <div className="flex justify-center gap-5 flex-wrap">
                <button className="px-7 py-3 text-lg border border-cyan-400 bg-gradient-to-br from-cyan-300/20 to-cyan-400/20 hover:from-cyan-300/40 hover:to-cyan-400/40 hover:shadow-[0_0_20px_rgba(0,212,255,0.5)] transition rounded">
                  Get Started
                </button>
                <button className="px-7 py-3 text-lg border border-white/20 bg-white/10 hover:bg-white/20 transition rounded">
                  Learn More
                </button>
              </div>
            </div>
          </section>

          {/* Featured Badge (Dynamic from Carousel) */}
          <section className="py-20">
            <h2 className="text-4xl mb-10 text-center">Featured Badge</h2>
            <div className="flex items-center gap-10 flex-wrap md:flex-nowrap text-text-light">
              <div className="flex-1 text-center md:text-left">
                <h3 className="text-2xl mb-5">{badges[activeIndex].title}</h3>
                <p className="text-text-medium text-lg leading-relaxed mb-8 max-w-lg mx-auto md:mx-0">
                  {badges[activeIndex].description}
                </p>
                <div className="flex gap-8 flex-wrap justify-center md:justify-start">
                  <div className="bg-white/5 rounded-lg p-4 text-center flex-1 min-w-[150px]">
                    <p className="text-2xl font-bold text-cyan-400 mb-1">150+</p>
                    <p className="text-sm text-text-medium">Holders</p>
                  </div>
                  <div className="bg-white/5 rounded-lg p-4 text-center flex-1 min-w-[150px]">
                    <p className="text-2xl font-bold text-cyan-400 mb-1">2024</p>
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
            <h2 className="text-4xl mb-10 text-center">All Badges</h2>
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

          {/* Features Section */}
          {/* Why Earn Badges Section */}
<section className="py-20 features-section bg-transparent">
  <div className="max-w-[1200px] mx-auto px-5">
    <h2 className="text-center text-4xl text-white mb-10 relative inline-block left-1/2 -translate-x-1/2">
      Why Earn Badges?
    </h2>
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 features-grid">
      <div className="p-8 flex flex-col items-center text-center transition-transform duration-300 hover:-translate-y-2 hover:shadow-xl glass-card bg-white/5 rounded-lg">
        <div className="text-5xl mb-5 bg-gradient-to-br from-cyan-400 to-teal-400 bg-clip-text text-transparent">
          🏆
        </div>
        <h3 className="text-xl text-white mb-3">Showcase Skills</h3>
        <p className="text-gray-300 text-base leading-relaxed">
          Display your verified cybersecurity skills and knowledge to employers and peers.
        </p>
      </div>
      <div className="p-8 flex flex-col items-center text-center transition-transform duration-300 hover:-translate-y-2 hover:shadow-xl glass-card bg-white/5 rounded-lg">
        <div className="text-5xl mb-5 bg-gradient-to-br from-cyan-400 to-teal-400 bg-clip-text text-transparent">
          🚀
        </div>
        <h3 className="text-xl text-white mb-3">Career Growth</h3>
        <p className="text-gray-300 text-base leading-relaxed">
          Advance your career by earning increasingly advanced badges in your field.
        </p>
      </div>
      <div className="p-8 flex flex-col items-center text-center transition-transform duration-300 hover:-translate-y-2 hover:shadow-xl glass-card bg-white/5 rounded-lg">
        <div className="text-5xl mb-5 bg-gradient-to-br from-cyan-400 to-teal-400 bg-clip-text text-transparent">
          🔍
        </div>
        <h3 className="text-xl text-white mb-3">Validate Expertise</h3>
        <p className="text-gray-300 text-base leading-relaxed">
          Prove your capabilities through practical challenges and assessments.
        </p>
      </div>
      <div className="p-8 flex flex-col items-center text-center transition-transform duration-300 hover:-translate-y-2 hover:shadow-xl glass-card bg-white/5 rounded-lg">
        <div className="text-5xl mb-5 bg-gradient-to-br from-cyan-400 to-teal-400 bg-clip-text text-transparent">
          🌐
        </div>
        <h3 className="text-xl text-white mb-3">Join Community</h3>
        <p className="text-gray-300 text-base leading-relaxed">
          Connect with other cybersecurity professionals in a growing community.
        </p>
      </div>
    </div>
  </div>
</section>

        </div>
      </div>
      <Footer />
    </>
  );
}
