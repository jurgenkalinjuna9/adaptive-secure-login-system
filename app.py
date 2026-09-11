import os
import time

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
# Temporary restriction duration used for KR1 testing.
# A short period keeps the prototype practical to evaluate.
KR1_RESTRICTION_SECONDS = 60

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
    Authenticate a registered user using username and password.

    The login process also records authentication events and
    counts consecutive failed login attempts.

    This failed-attempt count forms the first risk indicator
    used by the adaptive authentication system.
    """

    if request.method == "POST":

        # Record when authentication processing begins.
        start_time = time.perf_counter()

        # Retrieve the submitted credentials.
        username = request.form["username"].strip()
        password = request.form["password"]

        # Record the IP address associated with this request.
        # During local testing this will normally be 127.0.0.1.
        ip_address = request.remote_addr

        connection = None
        cursor = None

        try:
            # Connect to MySQL.
            connection = get_db_connection()

            # Return database results as dictionaries.
            cursor = connection.cursor(dictionary=True)

            # -------------------------------------------------
            # FIND THE USER
            # -------------------------------------------------

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
            # KR1: CHECK FOR ACTIVE TEMPORARY RESTRICTION
            # -------------------------------------------------

            # Find the most recent KR1 restriction trigger for
            # this username. Only the trigger event is checked,
            # so repeated blocked attempts do not extend the timer.
            cursor.execute(
                """
                SELECT
                    TIMESTAMPDIFF(
                        SECOND,
                        created_at,
                        NOW()
                    ) AS seconds_since_restriction
                FROM login_attempts
                WHERE username = %s
                AND action_taken = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                   username,
                   "Temporary restriction recommended"
                )
            )

            restriction = cursor.fetchone()

            if restriction:

                seconds_since_restriction = (
                    restriction["seconds_since_restriction"]
                )

                if (
                     seconds_since_restriction
                     < KR1_RESTRICTION_SECONDS
                ):

                      flash(
                          "Login temporarily restricted due to repeated failed attempts. Please try again shortly.",
                          "error"
                      )

                      return render_template("login.html")
            # -------------------------------------------------
            # SUCCESSFUL AUTHENTICATION
            # -------------------------------------------------

            if user and check_password_hash(
                user["password_hash"],
                password
            ):

                response_time_ms = (
                    time.perf_counter() - start_time
                ) * 1000

                # A successful login starts a new authentication
                # sequence, so the consecutive failure count is 0.
                failed_attempts = 0

                cursor.execute(
                    """
                    INSERT INTO login_attempts (
                        user_id,
                        username,
                        ip_address,
                        success,
                        failed_attempts,
                        action_taken,
                        response_time_ms
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        user["id"],
                        username,
                        ip_address,
                        True,
                        failed_attempts,
                        "Login allowed",
                        response_time_ms
                    )
                )

                connection.commit()

                # Create the authenticated Flask session.
                session["user_id"] = user["id"]
                session["username"] = user["username"]

                flash(
                    "Login successful.",
                    "success"
                )

                return redirect(url_for("dashboard"))

            # -------------------------------------------------
            # FAILED LOGIN ATTEMPT
            # -------------------------------------------------

            # Find the most recent successful login for this
            # username. Any failures after this point belong
            # to the current failed-login sequence.
            cursor.execute(
                """
                SELECT MAX(id) AS last_success_id
                FROM login_attempts
                WHERE username = %s
                AND success = 1
                """,
                (username,)
            )

            result = cursor.fetchone()

            last_success_id = result["last_success_id"]

            # If the account has never logged in successfully,
            # start counting from the beginning of its history.
            if last_success_id is None:
                last_success_id = 0

            # Count previous failed attempts that occurred after
            # the most recent successful authentication.
            cursor.execute(
                """
                SELECT COUNT(*) AS failure_count
                FROM login_attempts
                WHERE username = %s
                AND success = 0
                AND id > %s
                """,
                (
                    username,
                    last_success_id
                )
            )

            result = cursor.fetchone()

            # Add the current failed attempt to the previous count.
            failed_attempts = result["failure_count"] + 1


            # -------------------------------------------------
            # KR1: FAILED-LOGIN RISK SCORE
            # -------------------------------------------------

            # Assign a risk contribution based on the number
            # of consecutive failed authentication attempts.
            #
            # 0-2 failures = 0 points
            # 3-4 failures = 2 points
            # 5+ failures  = 4 points
            if failed_attempts >= 5:
                risk_score = 4
                risk_level = "High"
                action_taken = "Temporary restriction recommended"

            elif failed_attempts >= 3:
                risk_score = 2
                risk_level = "Medium"
                action_taken = "Additional verification recommended"

            else:
               risk_score = 0
               risk_level = "Low"
               action_taken = "Login rejected"


           # Measure the total authentication processing time.
            response_time_ms = (
               time.perf_counter() - start_time
            ) * 1000

            # If the username exists, associate the attempt
            # with the corresponding user ID.
            # Unknown usernames are stored with user_id = NULL.
            user_id = user["id"] if user else None

            # Record the failed authentication attempt.
            cursor.execute(
                """
                INSERT INTO login_attempts (
                    user_id,
                    username,
                    ip_address,
                    success,
                    failed_attempts,
                    risk_score,
                    risk_level,
                    action_taken,
                    response_time_ms
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    username,
                    ip_address,
                    False,
                    failed_attempts,
                    risk_score,
                    risk_level,
                    action_taken,
                    response_time_ms
                )
            )

            connection.commit()

            # Display a response based on the detected KR1 risk level.
            if risk_level == "High":

                flash(
                   "High-risk login activity detected. Access is temporarily restricted.",
                   "error"
                )

            elif risk_level == "Medium":

                flash(
                   "Multiple failed login attempts detected. Additional verification may be required.",
                   "error"
                )

            else:

                flash(
                   "Invalid username or password.",
                   "error"
                )
        finally:

            # Always release database resources.
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