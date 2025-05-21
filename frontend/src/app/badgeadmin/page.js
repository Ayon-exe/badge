'use client';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import React, { useState } from 'react';
import { FaTrashAlt } from 'react-icons/fa';

const TABS = ['Personal', 'Members', 'Integration', 'Billing'];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState('Members');

  const renderTabContent = () => {
    switch (activeTab) {
      case 'Personal':
        return <p className="text-gray-600">Personal settings go here...</p>;
      case 'Integration':
        return <p className="text-gray-600">Integration settings go here...</p>;
      case 'Billing':
        return <p className="text-gray-600">Billing information goes here...</p>;
      case 'Members':
        return (
          <div className="flex flex-col lg:flex-row justify-between gap-6 mb-6">
            {/* Left side - Description and buttons */}
            <div className="flex flex-col justify-between space-y-4 lg:max-w-sm">
              <div>
                <p className="text-gray-700 text-sm">
                  Invite your team members on Nuck to work faster and collaborate easily together.
                </p>
                <p className="text-gray-500 text-sm">
                  Manage their permissions to better structure projects.
                </p>
              </div>
              <div className="space-x-2">
                <button className="bg-blue-500 text-white text-sm px-4 py-1 rounded">Upload CSV</button>
                <button className="bg-green-700 text-white text-sm px-4 py-1 rounded">
                  Download Template
                </button>
              </div>
            </div>

            {/* Right side - CSV Preview Card */}
            <div className="flex-1">
              <div className="w-full h-64 border border-dashed border-gray-400 rounded-lg bg-white/5 flex items-center justify-center text-gray-400">
                CSV Preview
              </div>
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <>
      <Navbar />
      <div className="min-h-full p-6">
        <h1 className="text-2xl font-bold mb-4">Admin</h1>

        <div className="border-b border-gray-300 mb-6 flex flex-wrap gap-4 text-sm">
          {TABS.map((tab) => (
            <button
              key={tab}
              className={`pb-2 ${
                activeTab === tab
                  ? 'border-b-2 border-black font-semibold'
                  : 'text-gray-500 hover:text-black'
              }`}
              onClick={() => setActiveTab(tab)}
            >
              {tab}
            </button>
          ))}
        </div>

        <div>{renderTabContent()}</div>
      </div>
      <Footer />
    </>
  );
}
