"use client";

import React, { createContext, useContext } from "react";
import useAuth from "../hooks/useAuth"; // Adjust the path to your `useAuth.js` file

// Create the AuthContext
const AuthContext = createContext();

// AuthProvider component
export const AuthProvider = ({ children }) => {
  const auth = useAuth(); // Call the custom useAuth hook

  return <AuthContext.Provider value={auth}>{children}</AuthContext.Provider>;
};

// Hook to use the AuthContext
export const useAuthContext = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuthContext must be used within an AuthProvider");
  }
  return context;
};
