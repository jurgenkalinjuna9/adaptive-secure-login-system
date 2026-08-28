from flask import Flask
from database import get_db_connection

# Create the Flask application.
app = Flask(__name__)


@app.route("/")
def home():
    """
    Test that Flask can communicate with the MySQL database.
    """

    # Open a connection to the adaptive_login database.
    connection = get_db_connection()

    # Create a cursor so Python can send SQL queries to MySQL.
    cursor = connection.cursor()

    # Ask MySQL for its current server version.
    cursor.execute("SELECT VERSION()")

    # Retrieve the result returned by MySQL.
    version = cursor.fetchone()

    # Close the database objects after the query.
    cursor.close()
    connection.close()

    # Display the database version in the browser.
    return f"Adaptive Secure Login System. MySQL version: {version[0]}"


if __name__ == "__main__":
    # Start the local Flask development server.
    app.run(debug=True)