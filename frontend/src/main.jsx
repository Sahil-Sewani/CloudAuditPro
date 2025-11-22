// frontend/src/main.jsx
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
    // When user hits /app and is not logged in, show login/signup
    return <AuthPage />;
  }

  // Logged in → show dashboard
  return <App user={user} onLogout={logout} />;
}

// Simple path-based routing without React Router
const path = window.location.pathname;

let app;

if (path.startsWith("/reset-password")) {
  app = <ResetPasswordPage />;
} else if (path.startsWith("/forgot-password")) {
  app = <ForgotPasswordPage />;
} else if (path === "/" || path.startsWith("/about")) {
  // Marketing/landing page
  app = <AboutPage />;
} else if (path.startsWith("/app")) {
  // Actual product app (login + dashboard behind auth)
  app = (
    <AuthProvider>
      <Root />
    </AuthProvider>
  );
} else {
  // Fallback: send unknown routes to landing
  app = <AboutPage />;
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>{app}</React.StrictMode>
);
