import React from 'react';

const ConfirmationModal = ({ isOpen, onClose, onConfirm, itemName }) => {
  if (!isOpen) return null;

  return (
  <div className="fixed inset-0 flex items-center justify-center z-50 backdrop-blur-sm bg-opacity-50">
    <div className="bg-slate-950/30 backdrop-blur-sm  p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-4">Confirm Deletion</h2>
      <p className="mb-4">Are you sure you want to delete the watchlist "{itemName}"?</p>
      <div className="flex justify-end m-4">
        <button 
           className="bg-[#3DB5DA] text-white px-4 py-2 rounded-lg hover:bg-[#2b9dc0] transition-colors m-4"
           onClick={onClose}>
          Cancel
        </button>
        <button 
          className="px-4 py-2 bg-red-500 text-white rounded m-4" 
          onClick={onConfirm}>
          Delete
        </button>
      </div>
    </div>
  </div>
  );
};

export default ConfirmationModal;
