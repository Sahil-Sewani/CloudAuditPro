import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./index.css";
import { AuthProvider, useAuth } from "./AuthContext.jsx";
import AuthPage from "./AuthPage.jsx";
import ForgotPasswordPage from "./ForgotPasswordPage.jsx";
import ResetPasswordPage from "./ResetPasswordPage.jsx";
import AboutPage from "./AboutPage.jsx";

function Root() {
  const { token, user, loading, logout } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-white">
        <div className="text-slate-300">Loading your session...</div>
      </div>
    );
  }

  if (!token) {
    return <AuthPage />;
  }

  // You can pass user/logout into App if you want to show user info in header
  return <App user={user} onLogout={logout} />;
}

// Simple path-based routing without React Router
const path = window.location.pathname;

let app;
if (path.startsWith("/reset-password")) {
  app = <ResetPasswordPage />;
} else if (path.startsWith("/forgot-password")) {
  app = <ForgotPasswordPage />;
} else if (path.startsWith("/about")) {
  // Public About page (no auth required)
  app = <AboutPage />;
} else {
  app = (
    <AuthProvider>
      <Root />
    </AuthProvider>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>{app}</React.StrictMode>
);
