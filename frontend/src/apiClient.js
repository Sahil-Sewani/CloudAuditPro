const API_BASE =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export async function apiFetch(
  path,
  { token, method = "GET", body, headers = {} } = {}
) {
  const finalHeaders = { ...headers };

  if (token) {
    finalHeaders["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: finalHeaders,
    body,
  });

  const text = await res.text(); // read body once
  let data = null;

  if (text) {
    try {
      data = JSON.parse(text);
    } catch (e) {
      data = { raw: text };
    }
  }

  if (!res.ok) {
    const message =
      (data && data.detail) ||
      (data && data.raw) ||
      `Request failed with status ${res.status}`;
    throw new Error(message);
  }

  return data;
}

