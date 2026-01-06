const logEl = document.getElementById('log');
function log(...args) {
  logEl.textContent += args.map(a => (typeof a === 'string' ? a : JSON.stringify(a, null, 2))).join(' ') + '\n';
}

function toArrayBuffer(x) {
  if (x instanceof ArrayBuffer) return x;
  if (ArrayBuffer.isView(x)) return x.buffer;
  throw new Error("Expected ArrayBuffer or view");
}

function bufferToBase64url(buf) {
  const bytes = new Uint8Array(toArrayBuffer(buf));
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function preformatCreateOptions(opts) {
  // opts is JSON from server
  opts.challenge = base64urlToBuffer(opts.challenge);
  opts.user.id = base64urlToBuffer(opts.user.id);

  if (opts.excludeCredentials) {
    opts.excludeCredentials = opts.excludeCredentials.map(c => ({
      ...c,
      id: base64urlToBuffer(c.id),
    }));
  }
  return opts;
}

function preformatGetOptions(opts) {
  opts.challenge = base64urlToBuffer(opts.challenge);
  if (opts.allowCredentials) {
    opts.allowCredentials = opts.allowCredentials.map(c => ({
      ...c,
      id: base64urlToBuffer(c.id),
    }));
  }
  return opts;
}

// SAFELY serialize registration credential (no recursive walking)
function serializeAttestation(cred) {
  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
      attestationObject: bufferToBase64url(cred.response.attestationObject),
      // Edge/Chrome may support this on attestation response
      transports: (typeof cred.response.getTransports === "function")
        ? cred.response.getTransports()
        : undefined,
    },
    clientExtensionResults: (typeof cred.getClientExtensionResults === "function")
      ? cred.getClientExtensionResults()
      : {},
  };
}

// SAFELY serialize login assertion
function serializeAssertion(assertion) {
  return {
    id: assertion.id,
    rawId: bufferToBase64url(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
      authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
      signature: bufferToBase64url(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? bufferToBase64url(assertion.response.userHandle)
        : null,
    },
    clientExtensionResults: (typeof assertion.getClientExtensionResults === "function")
      ? assertion.getClientExtensionResults()
      : {},
  };
}

async function postJSON(url, data) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(data),
  });

  const payload = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(payload.detail || res.statusText);
  return payload;
}

async function registerPasskey() {
  const username = document.getElementById('username').value.trim();
  if (!username) return alert('Enter username');

  log('1) Requesting registration options...');
  const opts = await postJSON('/api/register/options', { username });

  log('2) navigator.credentials.create()...');
  const publicKey = preformatCreateOptions(opts);
  const cred = await navigator.credentials.create({ publicKey });

  log('3) Sending attestation to server...');
  const credJSON = serializeAttestation(cred);
  const result = await postJSON('/api/register/verify', { username, credential: credJSON });

  log('Registered:', result);
}

async function loginPasskey() {
  const username = document.getElementById('username').value.trim();
  if (!username) return alert('Enter username');

  log('1) Requesting login options...');
  const opts = await postJSON('/api/login/options', { username });

  log('2) navigator.credentials.get()...');
  const publicKey = preformatGetOptions(opts);
  const assertion = await navigator.credentials.get({ publicKey });

  log('3) Sending assertion to server...');
  const assertionJSON = serializeAssertion(assertion);

  // For replay testing
  window.__lastAssertion = assertionJSON;
  log('Captured assertion in window.__lastAssertion (for replay testing).');

  const result = await postJSON('/api/login/verify', { credential: assertionJSON });

  log('Logged in:', result);
}

async function whoAmI() {
  const res = await fetch('/api/me', { credentials: 'include' });
  const data = await res.json();
  log('ME:', data);
}

async function logout() {
  const data = await postJSON('/api/logout', {});
  log('LOGOUT:', data);
}

document.getElementById('btnRegister').onclick = () => registerPasskey().catch(e => log('ERROR:', e.message));
document.getElementById('btnLogin').onclick = () => loginPasskey().catch(e => log('ERROR:', e.message));
document.getElementById('btnMe').onclick = () => whoAmI().catch(e => log('ERROR:', e.message));
document.getElementById('btnLogout').onclick = () => logout().catch(e => log('ERROR:', e.message));