"use client"
import { useAuthContext } from "@/components/AuthContext";
import { useEffect, useState } from "react";
import { FaUserCircle, FaPencilAlt } from "react-icons/fa"; // Default icon for missing profile picture
const ProfilePage = () => {
  const [activeTab, setActiveTab] = useState('profile');
  const [profilePic, setProfilePic] = useState(null);
  const [username, setUsername] = useState('JohnDoe123');
  const [accountDate, setAccountDate] = useState('January 15, 2022');
  const { user, loading, logout } = useAuthContext();
  const [userID, setUserID] = useState("");


   // Set user ID when component mounts
    useEffect(() => {
      if (user && !loading) {
        setUserID(user.username || user.email || "User" + Math.floor(Math.random() * 10000));
      }
    }, [user, loading]);


  const handleTabChange = (tab) => {
    setActiveTab(tab);
  };

  const handleProfilePicChange = (e) => {
    setProfilePic(e.target.files[0]);
  };

  const handlePersonalInfoSubmit = (e) => {
    e.preventDefault();
    alert('Personal information updated successfully.');
  };

  const handlePasswordResetSubmit = (e) => {
    e.preventDefault();
    const current = e.target.currentPassword.value.trim();
    const newPass = e.target.newPassword.value.trim();
    const confirmPass = e.target.confirmPassword.value.trim();

    if (!current || !newPass || !confirmPass) {
      alert('Please fill in all password fields.');
      return;
    }
    if (newPass !== confirmPass) {
      alert('New passwords do not match.');
      return;
    }
    if (newPass.length < 6) {
      alert('New password must be at least 6 characters.');
      return;
    }
    // Simulate password reset success
    alert('Password has been reset successfully.');
    e.target.reset();
  };

  return (
    <div className="flex h-screen">
      <div className="w-64 bg-gray-800 text-white p-4">
        <h2 className="text-lg font-bold mb-4">User  Menu</h2>
        <ul>
          <li
            className={activeTab === 'profile' ? 'bg-gray-900 p-2 rounded cursor-pointer' : 'p-2 rounded cursor-pointer'}
            onClick={() => handleTabChange('profile')}
          >
            Profile
          </li>
          <li
            className={activeTab === 'personal' ? 'bg-gray-900 p-2 rounded cursor-pointer' : 'p-2 rounded cursor-pointer'}
            onClick={() => handleTabChange('personal')}
          >
            Personal Info
          </li>
          <li
            className={activeTab === 'security' ? 'bg-gray-900 p-2 rounded cursor-pointer' : 'p-2 rounded cursor-pointer'}
            onClick={() => handleTabChange('security')}
          >
            Security
          </li>
          <li
            className={activeTab === 'payment' ? 'bg-gray-900 p-2 rounded cursor-pointer' : 'p-2 rounded cursor-pointer'}
            onClick={() => handleTabChange('payment')}
          >
            Payment
          </li>
        </ul>
      </div>
      <main className="flex-1 p-4">
        {activeTab === 'profile' && (
          <div>
            <h1 className="text-2xl font-bold mb-4">Profile</h1>
            <div className="flex justify-center mb-4 relative">
  <FaUserCircle className="w-32 h-32   object-cover transition-opacity duration-300" />
  <input
    type="file"
    id="profile-pic-input"
    accept="image/*"
    onChange={handleProfilePicChange}
    className="absolute top-0 left-0 w-full h-full opacity-0 cursor-pointer hover:opacity-50"
  />
  <div className="absolute top-0 left-0 w-full h-full flex justify-center items-center opacity-0 hover:opacity-100 transition-opacity duration-300">
    <FaPencilAlt className="w-20 h-20 rounded-full object-cover transition-opacity duration-300 text-lg text-gray-500 cursor-pointer" />
  </div>
</div>
            <div className="mb-4">
              <div className="font-bold mb-1">Username</div>
              <div className="text-lg">{userID}</div>
            </div>
            <div className="mb-4">
              <div className="font-bold mb-1">Account Created</div>
              <div className="text-lg">{accountDate}</div>
            </div>
          </div>
        )}
        {activeTab === 'personal' && (
          <div>
            <h1 className="text-2xl font-bold mb-4">Personal Info</h1>
            <form onSubmit={handlePersonalInfoSubmit}>
              <div className="mb-4">
                <label className="block font-bold mb-1" htmlFor="full-name">Full Name</label>
                <input 
                  type="text" 
                  id="full-name" 
                  name="fullName" 
                  placeholder="John Doe" 
                  value={user.name} 
                  onChange={(e) => setUser({ ...user, name: e.target.value })} 
                  className="w-full p-2 rounded border border-gray-400" 
                />
              </div>
              <div className="mb-4">
                <label className="block font-bold mb-1" htmlFor="email">Email Address</label>
                <input 
                  type="email" 
                  id="email" 
                  name="email" 
                  placeholder="email@example.com" 
                  value={userID} 
                  onChange={(e) => setUserID(e.target.value)} 
                  className="w-full p-2 rounded border border-gray-400" 
                />
              </div>
              <div className="mb-4">
                <label className="block font-bold mb-1" htmlFor="phone">Phone Number</label>
                <input 
                  type="tel" 
                  id="phone" 
                  name="phone" 
                  placeholder="+1 555 123 4567" 
                  value={user.phone} 
                  onChange={(e) => setUser({ ...user, phone: e.target.value })} 
                  className="w-full p-2 rounded border border-gray-400" 
                />
              </div>
              <button type="submit" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Save Changes</button>
            </form>
          </div>
        )}
        {activeTab === 'security' && (
          <div>
            <h1 className="text-2xl font-bold mb-4">Security</h1>
            <form onSubmit={handlePasswordResetSubmit}>
              <div className="mb-4">
                <label className="block font-bold mb-1" htmlFor="current-password">Current Password</label>
                <input type="password" id="current-password" name="currentPassword" placeholder="Enter current password" required className="w-full p-2 rounded border border-gray-400" />
              </div>
              <div className="mb-4">
                <label className="block font-bold mb-1" htmlFor="new-password">New Password</label>
                <input type="password" id="new-password" name="newPassword" placeholder="Enter new password" required className="w-full p-2 rounded border border-gray-400" />
              </div>
              <div className="mb-4">
                <label className="block font-bold mb-1" htmlFor="confirm-password">Confirm New Password</label>
                <input type="password" id="confirm-password" name="confirmPassword" placeholder="Confirm new password" required className="w-full p-2 rounded border border-gray-400" />
              </div>
              <button type="submit" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Reset Password</button>
            </form>
          </div>
        )}
        {activeTab === 'payment' && (
          <div>
            <h1 className="text-2xl font-bold mb-4">Payment</h1>
            <div className="mb-4">
              <div className="font-bold mb-1">Saved Payment Methods</div>
              <div className="text-lg">Visa ending in 1234</div>
              <div className="text-lg">Expires 09/25</div>
            </div>
            <div className="mb-4">
              <div className="font-bold mb-1">Recent Transactions</div>
              <div className="text-lg">Jan 5, 2024 - Subscription Renewal - $9.99</div>
              <div className="text-lg">Dec 10, 2023 - Product Purchase - $49.99</div>
            </div>
            <button type="button" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Add Payment Method</button>
          </div>
        )}
      </main>
    </div>
  );
};

export default ProfilePage;