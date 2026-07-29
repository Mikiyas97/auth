document.addEventListener('DOMContentLoaded', function() {

    let loginButton = document.getElementById("login_btn");
    let loginForm = document.getElementById("login_form");

    if (loginButton) {
        loginButton.addEventListener("click", function(event) {
            event.preventDefault();
            loginForm.submit();
        });

        };
    });
