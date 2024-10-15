// Common function to retrieve all cookies
function getCookies() {
    const cookies = {};
    document.cookie.split(';').forEach(cookie => {
        const [name, value] = cookie.trim().split('=');
        cookies[name] = value;
    });
    return cookies;
}

// Function for main.html
function checkSessionAuth() {
    const cookies = getCookies();
    const sessionAuth = cookies['session_auth'];
    if (sessionAuth !== 'true') {
        window.location.href = '/pin';
    }
}

// Function for index.html
function checkAccess() {
    const cookies = getCookies();
    const secretCookie = cookies['secret'];
    const encryptCookie = cookies['encrypt'];
    if (secretCookie && encryptCookie) {
        window.location.href = '/';
    } else {
        setTimeout(checkAccess, 5000); // Check again after 5 seconds
    }
}

// Determine which page we're on and run the appropriate function
if (window.location.pathname.includes('index.html')) {
    checkSessionAuth();
    setInterval(checkSessionAuth, 3600000);
} else if (window.location.pathname.includes('/main.html')) {
    checkAccess();
}
