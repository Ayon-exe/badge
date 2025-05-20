import SessionProviderWrapper from "@/components/SessionProviderWrapper";
import { AuthProvider } from "@/components/AuthContext";
import "react-toastify/dist/ReactToastify.css";
import { ToastContainer } from "react-toastify";
import { WatchlistProvider } from "@/context/WatchlistContext";
import "./globals.css";

export const metadata = {
  title: "DeepCytes",
  description: "DeepCytes CVE Explorer",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ backgroundColor: "#00011e" }}>
        <SessionProviderWrapper>
          <AuthProvider>
            <WatchlistProvider>
              {children}
              <ToastContainer
                position="top-right"
                autoClose={5000}
                hideProgressBar={false}
                newestOnTop={false}
                closeOnClick
                rtl={false}
                pauseOnFocusLoss
                draggable
                pauseOnHover
                theme="colored"
              />
            </WatchlistProvider>
          </AuthProvider>
        </SessionProviderWrapper>
      </body>
    </html>
  );
}
