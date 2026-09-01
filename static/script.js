
// =====================================================
// PASSWORD VISIBILITY CONTROL
// =====================================================

/*
    Shows or hides the selected password field.

    Password fields are hidden by default using type="password".
    When the user clicks the Show button, the field changes
    temporarily to type="text" so the password can be checked.

    This only changes how the password appears in the browser.
    It does not affect password hashing or database storage.
*/
function togglePassword(fieldId, button) {

    // Find the password input using the ID supplied by the HTML.
    const passwordField = document.getElementById(fieldId);

    // Check whether the password is currently hidden.
    if (passwordField.type === "password") {

        // Make the password visible.
        passwordField.type = "text";

        // Change the button so the user can hide it again.
        button.textContent = "Hide";
        button.setAttribute("aria-label", "Hide password");

    } else {

        // Hide the password again.
        passwordField.type = "password";

        // Restore the original button text.
        button.textContent = "Show";
        button.setAttribute("aria-label", "Show password");
    }
}