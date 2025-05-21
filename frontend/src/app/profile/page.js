"use client"
import React, { useEffect, useState, useContext } from "react";
import { useParams, useRouter, Link } from "next/navigation";
//import UserBadges from "./UserBadges";
import Navbar from "@/components/Navbar";
import Footer from '@/components/Footer';
//import api from '../utils/api';
// import { AuthContext } from "../context/AuthContext";

const ProfilePage = () => {
  const { username } = useParams();
  const router = useRouter();
  const [user, setUser] = useState(null);
  const [badges, setBadges] = useState([]);
  const [recentBadges, setRecentBadges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("badges");
  
  // Get auth state from context
  // const { isAuthenticated} = useContext(AuthContext);

  // Fetch user details and earned badges from backend
  useEffect(() => {
    // Check if user is logged in using AuthContext
    // if (!isAuthenticated) {
    //   router.push("/login");
    //   return;
    // }

    const fetchUserData = async () => {
      try {
        setLoading(true);
        
        // First fetch user details
        try {
          const userResponse = await api.get(`/user`);
          setUser(userResponse.data);
        } catch (userErr) {
          console.log("Could not fetch detailed user info:", userErr);
          // Fall back to just using the username from the URL
          setUser({ username: username });
        }
        
        // Then fetch earned badges
        try {
          const badgesResponse = await api.get(`/badges-earned`);
          console.log("Badge response data:", badgesResponse.data);
          
          // The API now returns complete badge objects including all metadata
          const badgesList = badgesResponse.data.badges || [];
          setBadges(badgesList);
          
          // Get recent badges (last 3)
          const sortedBadges = [...badgesList].sort((a, b) => 
            new Date(b.earnedDate) - new Date(a.earnedDate)
          );
          setRecentBadges(sortedBadges.slice(0, 3));
          
        } catch (badgeErr) {
          console.error("Error fetching badges:", badgeErr);
          
          if (badgeErr.response?.status === 404) {
            setBadges([]);
            setRecentBadges([]);
          } else {
            setError("Failed to load badges. Please try again later.");
          }
        }
      } catch (err) {
        console.error("Error in main fetch routine:", err);
        setError("An unexpected error occurred. Please try again later.");
      } finally {
        setLoading(false);
      }
    };

    fetchUserData();
  }, [username, router]);

  // Format date helper
  const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
  };
  
  // Generate avatar initials
  const getInitials = (name) => {
    return name ? name.charAt(0).toUpperCase() : "U";
  };
  
  // Calculate badge stats
  const calculateStats = () => {
    if (!badges || badges.length === 0) {
      return {
        total: 0,
        recent: 0,
        progress: 0
      };
    }
    
    return {
      total: badges.length,
      recent: recentBadges.length,
      progress: Math.min(Math.round((badges.length / 8) * 100), 100) // Assuming 8 total badges
    };
  };
  
  const stats = calculateStats();

  if (loading) {
    return (
      <div className="profile-loading">
        <div className="loading-spinner"></div>
        <p>Loading profile...</p>
      </div>
    );
  }

  return (
    <div className="profile-page">
      <Navbar />
      
      <div className="profile-container">
        <div className="profile-grid">
          {/* Left column - User info */}
          <div className="profile-sidebar glass-card">
            <div className="profile-header">
              <div className="profile-avatar">
                {getInitials(username)}
              </div>
              <h2>{user?.username}</h2>
              {user?.email && <p className="profile-email">{user.email}</p>}
            </div>
            
            <div className="profile-stats">
              <div className="stat-item">
                <div className="stat-value">{stats.total}</div>
                <div className="stat-label">Total Badges</div>
              </div>
              
              <div className="stat-item">
                <div className="stat-value">{stats.recent}</div>
                <div className="stat-label">Recent</div>
              </div>
              
              <div className="stat-item progress-stat">
                <div className="progress-bar">
                  <div 
                    className="progress-fill" 
                    style={{width: `${stats.progress}%`}}
                  ></div>
                </div>
                <div className="stat-label">{stats.progress}% Complete</div>
              </div>
            </div>
            
            <div className="profile-actions">
              <Link className="glass-button">
                Edit Profile
              </Link>
              <Link to="/badges" className="glass-button">
                All Badges
              </Link>
            </div>
          </div>
          
          {/* Right column - Badges and content */}
          <div className="profile-content">
            {/* Tabs */}
            <div className="profile-tabs">
              <button 
                className={`tab-button ${activeTab === 'badges' ? 'active' : ''}`}
                onClick={() => setActiveTab('badges')}
              >
                Badges
              </button>
              <button 
                className={`tab-button ${activeTab === 'achievements' ? 'active' : ''}`}
                onClick={() => setActiveTab('achievements')}
              >
                Achievements
              </button>
              {/* <button 
                className={`tab-button ${activeTab === 'history' ? 'active' : ''}`}
                onClick={() => setActiveTab('history')}
              >
                History
              </button> */}
            </div>
            
            {/* Tab content */}
            <div className="tab-content glass-card">
              {activeTab === 'badges' && (
                <div className="badges-tab">
                  <h3>My Badges Collection</h3>
                  {error ? (
                    <p className="error-message">{error}</p>
                  ) : (
                    <UserBadges 
                      badges={badges} 
                      size="medium" 
                      showDates={true} 
                      badgeActions={(badge) => (
                        <Link 
                          to={`/learn-more?id=${badge._id}`}
                          className="glass-button text-sm mt-2 w-full text-center"
                        >
                          View in 3D
                        </Link>
                      )}
                    />
                  )}
                </div>
              )}
              
              {activeTab === 'achievements' && (
                <div className="achievements-tab">
                  <h3>Achievements</h3>
                  <p className="coming-soon">Achievements feature coming soon!</p>
                </div>
              )}
              
              {activeTab === 'history' && (
                <div className="history-tab">
                  <h3>Badge History</h3>
                  {badges.length === 0 ? (
                    <p className="no-history">No badges earned yet</p>
                  ) : (
                    <div className="badge-history">
                      {[...badges]
                        .sort((a, b) => new Date(b.earnedDate) - new Date(a.earnedDate))
                        .map((badge) => (
                          <div key={badge.id} className="history-item">
                            <div className="history-badge-icon">
                              <img src={badge.image} alt={badge.name} />
                            </div>
                            <div className="history-badge-info">
                              <h4>{badge.name}</h4>
                              <p>Earned on {formatDate(badge.earnedDate)}</p>
                              {badge.difficulty && (
                                <p className="badge-difficulty">Difficulty: {badge.difficulty}</p>
                              )}
                            </div>
                            <div className="history-badge-actions">
                              <Link 
                                to={`/badge-view/${badge.id}`}
                                className="glass-button text-sm py-1 px-3"
                              >
                                View in 3D
                              </Link>
                            </div>
                          </div>
                        ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      <Footer/>
    </div>
  );
};

export default ProfilePage;
