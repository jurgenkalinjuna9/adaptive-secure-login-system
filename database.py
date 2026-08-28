import os
import mysql.connector
from dotenv import load_dotenv

# Load variables from the .env file.
# This lets us keep the MySQL password outside the Python source code.
load_dotenv()


def get_db_connection():
    """
    Create and return a connection to the adaptive_login database.

    This function is reused whenever the Flask application
    needs to communicate with MySQL.
    """

    # Read the MySQL password from the .env file.
    mysql_password = os.getenv("MYSQL_PASSWORD")

    # Connect to the local MySQL server.
    connection = mysql.connector.connect(
        host="127.0.0.1",
        port=3306,
        user="root",
        password=mysql_password,
        database="adaptive_login"
    )

    # Return the active connection to whichever part
    # of the application requested database access.
    return connection