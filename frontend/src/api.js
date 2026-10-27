export function authHeaders() {
  const token = sessionStorage.getItem('kavach.accessToken');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function apiRequest(url, options = {}) {
  const response = await fetch(url, {
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
