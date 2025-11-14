import React, { createContext, useContext, useEffect, useState } from "react";

const AuthContext = createContext(null);

// Change this later to your production API, e.g. https://api.cloudauditpro.app
const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem("cap_token"));
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(!!token);
  const [error, setError] = useState("");

  // Fetch /auth/me whenever token changes
  useEffect(() => {
    if (!token) {
      setUser(null);
      localStorage.removeItem("cap_token");
      setLoading(false);
      return;
    }

    setLoading(true);
    localStorage.setItem("cap_token", token);

    fetch(`${API_BASE}/auth/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        setUser(data);
        setLoading(false);
      })
      .catch(() => {
        setUser(null);
        setToken(null);
        localStorage.removeItem("cap_token");
        setLoading(false);
      });
  }, [token]);

  const login = async (email, password) => {
    setError("");

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
    setToken(data.access_token);
    setError("");
  };

  const register = async (name, email, password) => {
    setError("");

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
    setToken(data.access_token);
    setError("");
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem("cap_token");
  };

  return (
    <AuthContext.Provider
      value={{ token, user, loading, error, login, register, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}

