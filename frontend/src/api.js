// Public build configuration only. Never place credentials in VITE_ variables.
const apiBase = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/$/, '');
export const backendMissing = import.meta.env.VITE_STATIC_HOST === 'true' && !apiBase;

export async function apiFetch(path, options = {}) {
  if (backendMissing) throw new Error('The public interface is available, but its backend has not been connected yet.');
  return fetch(`${apiBase}${path}`, options);
}

export function authHeaders() {
  const token = sessionStorage.getItem('kavach.accessToken');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function apiRequest(url, options = {}) {
  const response = await apiFetch(url, {
    ...options,
    headers: { ...authHeaders(), ...options.headers },
  });
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(response.ok ? 'The server returned an unreadable response.' : `The server could not complete this request (${response.status}).`);
  }
  if (!response.ok) {
    const detail = Array.isArray(data?.detail)
      ? data.detail.map(item => `${item.loc?.join('.') || 'request'}: ${item.msg}`).join('; ')
      : data?.detail;
    throw new Error(typeof detail === 'string' ? detail : `Request failed (${response.status})`);
  }
  if (data == null) throw new Error('The server returned an empty response.');
  return data;
}
