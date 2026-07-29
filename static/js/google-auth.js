document.addEventListener('DOMContentLoaded', function() {
    const googleBtns = document.querySelectorAll('.google-signin-btn');

    googleBtns.forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Sign in with Google Popup
            auth.signInWithPopup(provider)
                .then((result) => {
                    // Get the Firebase ID Token
                    return result.user.getIdToken();
                })
                .then((idToken) => {
                    // Send the token to our backend
                    return fetch('/google-login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ token: idToken })
                    });
                })
                .then(response => {
                    if (response.ok) {
                        // Backend verified token and issued JWT cookies. Redirect to home.
                        window.location.href = '/home';
                    } else {
                        response.json().then(data => {
                            alert("Login failed: " + (data.error || 'Unknown error'));
                        });
                    }
                })
                .catch((error) => {
                    console.error("Google Sign-In Error:", error);
                    // Only show alert if it's not simply the user closing the popup
                    if (error.code !== 'auth/popup-closed-by-user') {
                        alert("Google Sign-In failed. Check console for details.");
                    }
                });
        });
    });
});
