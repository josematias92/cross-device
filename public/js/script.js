function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// Tab switching
document.getElementById('register-tab').addEventListener('click', () => {
  document.getElementById('register-section').classList.add('active');
  document.getElementById('login-section').classList.remove('active');
});

document.getElementById('login-tab').addEventListener('click', () => {
  document.getElementById('login-section').classList.add('active');
  document.getElementById('register-section').classList.remove('active');
});

// Registration
document.getElementById('register-button').addEventListener('click', async () => {
  const email = document.getElementById('register-email').value;
  if (!email) {
    alert('Email is required');
    return;
  }
  const registerButton = document.getElementById('register-button');
  registerButton.disabled = true;
  registerButton.innerHTML = 'Registering...';
  try {
    const response = await fetch('/auth/start-registration', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
      credentials: 'include'
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const options = await response.json();
    const registration = await navigator.credentials.create({
      publicKey: options
    });
    const id = arrayBufferToBase64(registration.id);
    const rawId = arrayBufferToBase64(registration.rawId);
    const responseClientDataJSON = arrayBufferToBase64(registration.response.clientDataJSON);
    const responseAttestationObject = arrayBufferToBase64(registration.response.attestationObject);
    const verifyResponse = await fetch('/auth/verify-registration', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        id,
        rawId,
        response: {
          clientDataJSON: responseClientDataJSON,
          attestationObject: responseAttestationObject
        },
        type: registration.type
      }),
      credentials: 'include'
    });
    if (verifyResponse.ok) {
      alert('Registration successful');
    } else {
      throw new Error(`Registration verification failed: ${await verifyResponse.text()}`);
    }
  } catch (error) {
    console.error(error);
    alert(`Error: ${error.message}`);
  } finally {
    registerButton.disabled = false;
    registerButton.innerHTML = 'Register';
  }
});

// Authentication
document.getElementById('login-button').addEventListener('click', async () => {
  const email = document.getElementById('login-email').value;
  if (!email) {
    alert('Email is required');
    return;
  }
  const loginButton = document.getElementById('login-button');
  loginButton.disabled = true;
  loginButton.innerHTML = 'Logging in...';
  try {
    const response = await fetch('/auth/start-auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
      credentials: 'include'
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const options = await response.json();
    const authentication = await navigator.credentials.get({
      publicKey: options
    });
    const id = arrayBufferToBase64(authentication.id);
    const rawId = arrayBufferToBase64(authentication.rawId);
    const responseAuthenticatorData = arrayBufferToBase64(authentication.response.authenticatorData);
    const responseClientDataJSON = arrayBufferToBase64(authentication.response.clientDataJSON);
    const responseSignature = arrayBufferToBase64(authentication.response.signature);
    const responseUserHandle = authentication.response.userHandle ? arrayBufferToBase64(authentication.response.userHandle) : null;
    const verifyResponse = await fetch('/auth/verify-auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        id,
        rawId,
        response: {
          authenticatorData: responseAuthenticatorData,
          clientDataJSON: responseClientDataJSON,
          signature: responseSignature,
          userHandle: responseUserHandle
        },
        type: authentication.type
      }),
      credentials: 'include'
    });
    if (verifyResponse.ok) {
      alert('Authentication successful');
    } else {
      throw new Error(`Authentication verification failed: ${await verifyResponse.text()}`);
    }
  } catch (error) {
    console.error(error);
    alert(`Error: ${error.message}`);
  } finally {
    loginButton.disabled = false;
    loginButton.innerHTML = 'Login';
  }
});
