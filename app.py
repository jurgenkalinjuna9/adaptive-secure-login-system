from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from mysql.connector import IntegrityError
from database import get_db_connection

# Create the Flask application.
app = Flask(__name__)

# Flask uses the secret key to securely sign session data and flash messages.
# We will later move this into the .env file with the other sensitive settings.
app.secret_key = "development-secret-key"


@app.route("/")
def home():
    """
    Basic home route used to confirm that the Flask application is running.
    """
    return redirect(url_for("register"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Register a new user.

    GET:
        Display the registration form.

    POST:
        Validate the submitted details.
        Hash the password.
        Store the new user securely in MySQL.
    """

    if request.method == "POST":

        # Remove unnecessary spaces from the username.
        username = request.form["username"].strip()

        # Retrieve both password fields.
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # ---------------------------------------------------------
        # INPUT VALIDATION
        # ---------------------------------------------------------

        # Ensure the username is not empty.
        if not username:
            flash("Please enter a username.", "error")
            return render_template("register.html")

        # Require a reasonable minimum username length.
        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "error")
            return render_template("register.html")

        # Require a minimum password length.
        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return render_template("register.html")

        # Ensure both password fields match.
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        # ---------------------------------------------------------
        # PASSWORD SECURITY
        # ---------------------------------------------------------

        # Generate a secure one-way password hash.
        # The original plaintext password is never stored.
        password_hash = generate_password_hash(password)

        connection = None
        cursor = None

        try:
            # Connect to the adaptive_login MySQL database.
            connection = get_db_connection()
            cursor = connection.cursor()

            # Parameterised SQL protects against SQL injection.
            cursor.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (%s, %s)
                """,
                (username, password_hash)
            )

            # Permanently save the new user.
            connection.commit()

            # Inform the user that registration succeeded.
            flash(
                "Account created successfully. You can now sign in.",
                "success"
            )

            # Send the user to the login page.
            return redirect(url_for("login"))

        except IntegrityError:

            # The username column is UNIQUE in the database.
            # If it already exists, MySQL raises an IntegrityError.
            flash(
                "That username is already registered. Please choose another.",
                "error"
            )

            return render_template("register.html")

        finally:

            # Always close database resources after use.
            if cursor:
                cursor.close()

            if connection:
                connection.close()

    return render_template("register.html")


@app.route("/login")
def login():
    """
    Temporary login page.

    Actual authentication logic will be implemented
    immediately after registration is complete.
    """
    return render_template("login.html")


if __name__ == "__main__":
    # Debug mode is suitable for local development only.
    app.run(debug=True)