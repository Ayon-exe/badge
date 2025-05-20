"use client"
import React, { useState, useEffect, useContext } from 'react';
import { useSearchParams } from 'next/navigation';
import { ChevronLeft, ChevronRight, Award, Share2, Shield, Code } from 'lucide-react';
import axios from 'axios';
import Navbar from "@/components/Navbar";
import Footer from '@/components/Footer';
import { useAuthContext } from "@/components/AuthContext";

const badgeid = () => {
  const searchParams = useSearchParams();
  const badgeId = searchParams.get('id');
  const [badges, setBadges] = useState([]);
  const [shareUrl, setShareUrl] = useState(null);
  const [earnedBadges, setEarnedBadges] = useState([]);
  const [currentBadgeIndex, setCurrentBadgeIndex] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [isDataLoading, setIsDataLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showShareSuccess, setShowShareSuccess] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 768);
  const [showLoginMessage, setShowLoginMessage] = useState(false);

 const { isAuthenticated, user } = useAuthContext();


  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 768);
    window.addEventListener('resize', handleResize);

    const fetchBadges = async () => {
      try {
        setIsDataLoading(true);

        const responseBadges = await axios.get(`${process.env.REACT_APP_SERVER_URL}/badges`);
        setBadges(responseBadges.data.badges);

        if (user?.username) {
          const token = localStorage.getItem('token');
          const responseEarnedBadges = await axios.get(
            `${process.env.REACT_APP_SERVER_URL}/badges-earned`,
            {
              headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
              },
              timeout: 10000,
            }
          );
          setEarnedBadges(responseEarnedBadges.data.badges || []);
        }
        setIsDataLoading(false);
      } catch (err) {
        console.error('Error fetching badges:', err);
        setError('Failed to load badges from database. Please try again later.');
        setIsDataLoading(false);
        setBadges([
          {
            id: 1,
            name: 'Cyber Titan Level I',
            image: '/images/img1.png',
            difficulty: 'Easy',
            description: 'Awarded for completing basic cybersecurity challenges.',
            category: 'Amateur',
            skillsEarned: ['Basic Security', 'Web Awareness'],
          },
          {
            id: 2,
            name: 'Cyber Warrior',
            image: '/images/img2.png',
            difficulty: 'Medium',
            description: 'Earned after passing the second level of security defenses.',
            category: 'Intermediate',
            skillsEarned: ['Network Security', 'Threat Identification'],
          },
          {
            id: 3,
            name: 'Cyber Defender',
            image: '/images/img3.jpg',
            difficulty: 'Medium',
            description: 'Awarded for identifying and mitigating cyber threats.',
            category: 'Intermediate',
            skillsEarned: ['Threat Prevention', 'Security Policy'],
          },
          {
            id: 4,
            name: 'Cyber Elite',
            image: '/images/img4.jpg',
            difficulty: 'Hard',
            description: 'For advanced penetration testing and security analysis.',
            category: 'Professional',
            skillsEarned: ['Penetration Testing', 'Vulnerability Assessment'],
          },
        ]);
      }
    };

    fetchBadges();

    return () => window.removeEventListener('resize', handleResize);
  }, [user]);

  const difficultyColors = {
    Easy: 'bg-green-500',
    Medium: 'bg-blue-600',
    Hard: 'bg-orange-500',
    Expert: 'bg-purple-700',
    Extreme: 'bg-red-600',
  };

  const getSkillIcon = (skill) => {
    if (skill === 'Basic Security') return <Shield className="w-5 h-5 mr-1" />;
    if (skill === 'Web Awareness') return <Code className="w-5 h-5 mr-1" />;
    return <Shield className="w-5 h-5 mr-1" />;
  };

  useEffect(() => {
    setIsLoading(true);
    const timer = setTimeout(() => setIsLoading(false), 1000);
    return () => clearTimeout(timer);
  }, [currentBadgeIndex]);

  useEffect(() => {
    if (badges.length > 0 && badgeId) {
      const index = badges.findIndex((b) => b._id === badgeId || b.id === badgeId);
      if (index !== -1) setCurrentBadgeIndex(index);
    }
  }, [badges, badgeId]);

  const currentBadge =
    badges.length > 0
      ? badges[currentBadgeIndex]
      : {
          id: 0,
          name: 'Loading...',
          image: '',
          difficulty: 'Medium',
          description: 'Loading badge information...',
          category: 'Loading...',
          skillsEarned: [],
        };

  const earnedBadge = earnedBadges.find((badge) => badge.id === currentBadge.id);

  if (isDataLoading) {
    return (
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <div className="flex-grow flex flex-col items-center justify-center">
          <div className="loader ease-linear rounded-full border-8 border-t-8 border-gray-200 h-16 w-16 mb-4 animate-spin"></div>
          <p className="text-gray-600 text-lg">Loading Badge Gallery...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-gray-900 text-white">
      <Navbar />
      <main className="flex flex-grow flex-col md:flex-row max-w-7xl mx-auto p-6 gap-6">
        {/* Left Column */}
        <section className="md:w-1/4 space-y-6">
          <h2 className="text-2xl font-semibold border-b border-gray-700 pb-2">Skills Earned</h2>
          <div className="grid grid-cols-1 gap-3">
            {currentBadge.skillsEarned?.map((skill, idx) => (
              <div
                key={idx}
                className="flex items-center bg-gray-800 rounded-md px-3 py-2 shadow-md"
              >
                {getSkillIcon(skill)}
                <span>{skill}</span>
              </div>
            ))}
          </div>

          <h2 className="text-2xl font-semibold border-b border-gray-700 pb-2">Badge Details</h2>
          <p className="text-gray-300 leading-relaxed">
            This badge recognizes excellence in cybersecurity fundamentals. Earners have
            demonstrated practical knowledge of core security concepts and have successfully
            applied these skills in various defensive scenarios.
          </p>
        </section>

        {/* Center Column */}
        <section className="md:w-2/4 flex flex-col items-center space-y-6">
          <div className="relative flex items-center justify-center w-full max-w-md">
            <button
              aria-label="Previous Badge"
              onClick={() =>
                setCurrentBadgeIndex((prev) => (prev === 0 ? badges.length - 1 : prev - 1))
              }
              className="absolute left-0 p-2 bg-gray-700 rounded-full hover:bg-gray-600 transition"
            >
              <ChevronLeft className="w-6 h-6" />
            </button>

            <div className="w-64 h-64 rounded-xl bg-gradient-to-tr from-indigo-700 via-purple-600 to-pink-600 shadow-lg flex items-center justify-center relative overflow-hidden">
              {!isLoading ? (
                <img
                  src={currentBadge.image}
                  alt={currentBadge.name}
                  className="max-w-full max-h-full object-contain"
                />
              ) : (
                <div className="loader ease-linear rounded-full border-8 border-t-8 border-gray-300 h-16 w-16 animate-spin"></div>
              )}
            </div>

            <button
              aria-label="Next Badge"
              onClick={() =>
                setCurrentBadgeIndex((prev) => (prev === badges.length - 1 ? 0 : prev + 1))
              }
              className="absolute right-0 p-2 bg-gray-700 rounded-full hover:bg-gray-600 transition"
            >
              <ChevronRight className="w-6 h-6" />
            </button>
          </div>

          {/* Hologram Base Rings */}
          <div className="relative w-64 h-12 mt-[-1rem]">
            <div className="absolute top-0 left-1/2 transform -translate-x-1/2 w-48 h-4 border-t-4 border-indigo-400 rounded-full opacity-70 animate-pulse"></div>
            <div className="absolute top-2 left-1/2 transform -translate-x-1/2 w-40 h-3 border-t-4 border-purple-400 rounded-full opacity-60 animate-pulse delay-150"></div>
            <div className="absolute top-4 left-1/2 transform -translate-x-1/2 w-32 h-2 border-t-4 border-pink-400 rounded-full opacity-50 animate-pulse delay-300"></div>
          </div>

          <h1 className="text-3xl font-bold text-center">{currentBadge.name}</h1>

          <div
            className={`inline-block px-4 py-1 rounded-full text-white font-semibold ${difficultyColors[currentBadge.difficulty]}`}
          >
            {currentBadge.difficulty}
          </div>

          <div className="w-full flex justify-around mt-4 space-x-4 text-center">
            <div className="bg-gray-800 rounded-md p-3 flex-1 shadow-md">
              <div className="text-sm uppercase text-gray-400">Level</div>
              <div className="text-lg font-semibold">{currentBadge.level || 'N/A'}</div>
            </div>
            <div className="bg-gray-800 rounded-md p-3 flex-1 shadow-md">
              <div className="text-sm uppercase text-gray-400">Branch</div>
              <div className="text-lg font-semibold">
                {currentBadge.skillsEarned[0] || 'General'}
              </div>
            </div>
            <div className="bg-gray-800 rounded-md p-3 flex-1 shadow-md">
              <div className="text-sm uppercase text-gray-400">Earners</div>
              <div className="text-lg font-semibold">43</div>
            </div>
          </div>
        </section>

        {/* Right Column */}
        <section className="md:w-1/4 space-y-6">
          <h2 className="text-2xl font-semibold border-b border-gray-700 pb-2">Badge Actions</h2>

          <div className="flex flex-col space-y-4">
            {earnedBadge ? (
              <>
                <div className="flex items-center space-x-2 bg-green-700 rounded-md p-3 shadow-md">
                  <Award className="w-6 h-6" />
                  <span>
                    {earnedBadge.earnedDate
                      ? `Earned on ${new Date(earnedBadge.earnedDate).toLocaleDateString()}`
                      : 'Not Earned Yet'}
                  </span>
                </div>

                <button
                  className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 transition rounded-md p-3 shadow-md"
                  onClick={() => {
                    if (!isAuthenticated) {
                      setShowLoginMessage(true);
                      setTimeout(() => setShowLoginMessage(false), 3000);
                      return;
                    }

                    const user = localStorage.getItem('user');
                    const userObject = user ? JSON.parse(user) : null;
                    if (!userObject) return;

                    const shareURL = `${window.location.origin}/badge/shared/${currentBadge.id}/${userObject.username}/${Math.floor(
                      Date.now() / 1000
                    )}`;
                    setShareUrl(shareURL);
                    setShowShareSuccess(true);
                    setTimeout(() => setShowShareSuccess(false), 3000);
                    navigator.clipboard.writeText(shareURL);
                  }}
                >
                  <Share2 className="w-6 h-6" />
                  <span>Generate Share Link</span>
                </button>
              </>
            ) : (
              <button
                className="flex items-center space-x-2 bg-indigo-600 hover:bg-indigo-700 transition rounded-md p-3 shadow-md"
                onClick={() => (window.location.href = 'https://learn.deepcytes.io/')}
              >
                <Award className="w-6 h-6" />
                <span>Get this Badge</span>
              </button>
            )}

            {showShareSuccess && (
              <div className="bg-green-600 text-white p-2 rounded-md text-center animate-pulse">
                Link generated! Share URL copied to clipboard.
              </div>
            )}

            {showLoginMessage && (
              <div className="bg-red-600 text-white p-2 rounded-md text-center animate-pulse">
                Please log in to generate a share link.
              </div>
            )}

            <h3 className="text-xl font-semibold border-b border-gray-700 pb-1 mt-6">Related Badges</h3>
            <div className="flex space-x-4 overflow-x-auto">
              {badges
                .filter((b) => b.id !== currentBadge.id)
                .slice(0, 3)
                .map((relatedBadge) => (
                  <div
                    key={relatedBadge.id}
                    className="flex-shrink-0 cursor-pointer flex flex-col items-center w-24 space-y-2"
                    onClick={() => {
                      const index = badges.findIndex((b) => b.id === relatedBadge.id);
                      if (index !== -1) setCurrentBadgeIndex(index);
                    }}
                    tabIndex={0}
                    role="button"
                    aria-pressed="false"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        const index = badges.findIndex((b) => b.id === relatedBadge.id);
                        if (index !== -1) setCurrentBadgeIndex(index);
                      }
                    }}
                  >
                    <img
                      src={relatedBadge.image}
                      alt={relatedBadge.name}
                      className="rounded-lg shadow-md w-20 h-20 object-cover"
                    />
                    <span className="text-sm text-center">{relatedBadge.name}</span>
                  </div>
                ))}
            </div>
          </div>
        </section>
      </main>

      {/* Badge Collection Thumbnails */}
      <div className="bg-gray-800 p-4 flex items-center justify-between max-w-7xl mx-auto">
        <div className="text-gray-300 text-sm">
          {badges.length} Badges — Showing {currentBadgeIndex + 1} of {badges.length}
        </div>

        <div className="flex space-x-2 overflow-x-auto max-w-[60vw]">
          {badges.map((badge, index) => (
            <img
              key={badge.id}
              src={badge.image}
              alt={badge.name}
              className={`w-14 h-14 object-cover rounded-md cursor-pointer shadow-md transition-transform ${
                index === currentBadgeIndex ? 'ring-4 ring-indigo-400 scale-110' : 'opacity-70'
              }`}
              onClick={() => setCurrentBadgeIndex(index)}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  setCurrentBadgeIndex(index);
                }
              }}
            />
          ))}
        </div>
      </div>

      <Footer />
    </div>
  );
};

export default badgeid;
