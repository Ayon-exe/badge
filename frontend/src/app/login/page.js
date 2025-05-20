import { LoginForm } from "@/components/login-form"
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";

export default function Page() {
  return (
    (
      <>
        <Navbar />
        <div className="h-full w-full bg-[url('/background.jpg')] bg-cover bg-center bg-fixed">
          <div className="text-white w-full justify-center items-center flex flex-col py-4 bg-blue-950/30 backdrop-blur-md shadow-lg rounded-lg">
            <LoginForm />
          </div>
          <Footer/>
        </div>
      </>
    )
  );
}
