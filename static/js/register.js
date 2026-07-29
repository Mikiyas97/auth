document.addEventListener('DOMContentLoaded', function() {
    let passwordInput = document.getElementById("password");
    let confirmPasswordInput = document.getElementById("confirm_password");
    let message = document.getElementById("message");
    let registerButton = document.getElementById("register_btn");
    let registraionForm = document.getElementById("register_form");

    let regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@.#$!%*?&])[A-Za-z\d@.#$!%*?&]{8,15}$/;


    function validatePassword() {
        if (!passwordInput || !confirmPasswordInput) return;
        if (passwordInput.value !== confirmPasswordInput.value) {
            message.textContent = "Passwords do not match";
            return false;

        } else {
            let weakStatus = regex.test(passwordInput.value)
            console.log(weakStatus)
            if(weakStatus == true){
                message.innerText = "strong password"
                return true;
            }
            else{
                message.innerText = "weak password"
                return false;
            }
        }
    }

    if (registerButton) {
        registerButton.addEventListener("click", function(event) {
            event.preventDefault();
            if(validatePassword()) {
                registraionForm.submit();
            }
        });
    }


});
