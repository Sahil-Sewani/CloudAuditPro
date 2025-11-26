// frontend/src/AuthContext.jsx
import React, { createContext, useContext, useEffect, useState } from "react";

const AuthContext = createContext(null);

// Change this later to your production API, e.g. https://api.cloudauditpro.app
const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "https://api.cloudauditpro.app";

// Max session lifetime in hours (front-end side)
const MAX_SESSION_HOURS = 8; // ← set to 8 for production
const SESSION_KEY = "cap_token";
const SESSION_ISSUED_KEY = "cap_token_issued_at";

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem(SESSION_KEY));
  const [sessionIssuedAt, setSessionIssuedAt] = useState(() => {
    const raw = localStorage.getItem(SESSION_ISSUED_KEY);
    return raw ? Number(raw) : null;
  });

  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(!!token);
  const [error, setError] = useState("");
  const [sessionExpired, setSessionExpired] = useState(false);

  // Helper: check if session is expired
  const isSessionExpired = () => {
    if (!token || !sessionIssuedAt) return false;
    const maxMs = MAX_SESSION_HOURS * 60 * 60 * 1000;
    return Date.now() - sessionIssuedAt > maxMs;
  };

  const clearSession = (reason) => {
    setToken(null);
    setUser(null);
    setError("");
    setLoading(false);
    setSessionIssuedAt(null);
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_ISSUED_KEY);

    if (reason === "expired") {
      setSessionExpired(true);
    } else {
      setSessionExpired(false);
    }
  };

  // Check expiry on mount / when token or issuedAt changes
  useEffect(() => {
    if (!token) {
      // No token → just ensure we're not "loading"
      setUser(null);
      setLoading(false);
      return;
    }

    if (isSessionExpired()) {
      clearSession("expired");
      return;
    }

    // Persist token + issuedAt if valid
    localStorage.setItem(SESSION_KEY, token);
    if (sessionIssuedAt) {
      localStorage.setItem(SESSION_ISSUED_KEY, String(sessionIssuedAt));
    }

    setLoading(true);

    fetch(`${API_BASE}/auth/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!data) {
          clearSession();
          return;
        }
        setUser(data);
        setLoading(false);
      })
      .catch(() => {
        clearSession();
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, sessionIssuedAt]);

  // Background interval to auto-logout when time passes while tab is open
  useEffect(() => {
    if (!token || !sessionIssuedAt) return;

    const interval = setInterval(() => {
      if (isSessionExpired()) {
        clearSession("expired");
      }
    }, 60 * 1000); // check every 60s

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, sessionIssuedAt]);

  const login = async (email, password) => {
    setError("");
    setSessionExpired(false); // clear banner on successful login attempt

    const body = new URLSearchParams();
    body.append("username", email);
    body.append("password", password);
    body.append("grant_type", "password");

    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setError(data.detail || "Invalid email or password");
      throw new Error("Login failed");
    }

    const data = await res.json();
    const now = Date.now();
    setToken(data.access_token);
    setSessionIssuedAt(now);
    localStorage.setItem(SESSION_KEY, data.access_token);
    localStorage.setItem(SESSION_ISSUED_KEY, String(now));
    setError("");
    setSessionExpired(false);
  };

  const register = async (name, email, password) => {
    setError("");
    setSessionExpired(false);

    const res = await fetch(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name, email, password }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setError(data.detail || "Registration failed");
      throw new Error("Registration failed");
    }

    const data = await res.json();
    const now = Date.now();
    setToken(data.access_token);
    setSessionIssuedAt(now);
    localStorage.setItem(SESSION_KEY, data.access_token);
    localStorage.setItem(SESSION_ISSUED_KEY, String(now));
    setError("");
    setSessionExpired(false);
  };

  const logout = () => {
    clearSession("manual");
  };

  return (
    <AuthContext.Provider
      value={{
        token,
        user,
        loading,
        error,
        login,
        register,
        logout,
        sessionExpired,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
