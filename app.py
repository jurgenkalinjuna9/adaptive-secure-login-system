import os

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)

from werkzeug.security import generate_password_hash, check_password_hash
from mysql.connector import IntegrityError
from dotenv import load_dotenv

from database import get_db_connection


# Load environment variables stored in the local .env file.
load_dotenv()


# Create the Flask application.
app = Flask(__name__)


# Flask uses this secret key to securely sign session data.
# The value is stored in .env rather than directly in the source code.
app.secret_key = os.getenv("FLASK_SECRET_KEY")

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


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Authenticate a registered user using the static
    username and password login process.

    GET:
        Display the login form.

    POST:
        Check the submitted credentials against
        the user record stored in MySQL.
    """

    if request.method == "POST":

        # Remove unnecessary spaces from the username.
        username = request.form["username"].strip()

        # Retrieve the password entered by the user.
        password = request.form["password"]

        connection = None
        cursor = None

        try:
            # Connect to the adaptive_login database.
            connection = get_db_connection()

            # dictionary=True allows us to access returned
            # database fields using their column names.
            cursor = connection.cursor(dictionary=True)

            # Retrieve the matching user account.
            # Parameterised SQL protects against SQL injection.
            cursor.execute(
                """
                SELECT id, username, password_hash
                FROM users
                WHERE username = %s
                """,
                (username,)
            )

            user = cursor.fetchone()

            # -------------------------------------------------
            # STATIC PASSWORD VERIFICATION
            # -------------------------------------------------

            # Only authenticate if the username exists
            # and the entered password matches the stored hash.
            if user and check_password_hash(
                user["password_hash"],
                password
            ):

                # Store the authenticated user's details
                # in the Flask session.
                session["user_id"] = user["id"]
                session["username"] = user["username"]

                flash(
                    "Login successful.",
                    "success"
                )

                # Temporary destination until the dashboard
                # route is implemented.
                return redirect(url_for("dashboard"))

            # Use one generic message for both an unknown
            # username and an incorrect password.
            #
            # This avoids revealing whether a particular
            # username exists in the system.
            flash(
                "Invalid username or password.",
                "error"
            )

        finally:

            # Always close database resources after use.
            if cursor:
                cursor.close()

            if connection:
                connection.close()

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    """
    Display the protected dashboard.

    Only users with a valid authenticated session
    are allowed to access this page.
    """

    # Check whether the user has successfully logged in.
    if "user_id" not in session:

        flash(
            "Please sign in to access the dashboard.",
            "error"
        )

        return redirect(url_for("login"))

    # Pass the authenticated username to the dashboard template.
    return render_template(
        "dashboard.html",
        username=session["username"]
    )


@app.route("/logout")
def logout():
    """
    End the authenticated user's session.
    """

    # Remove all stored session data.
    session.clear()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect(url_for("login"))

if __name__ == "__main__":
    # Debug mode is suitable for local development only.
    app.run(debug=True)