import mysql.connector
from mysql.connector import Error

def get_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",         
            password="cy6er",          
            database="cy6er"
        )
        if conn.is_connected():
            print("Connected to MariaDB!")
            return conn

    except Error as e:
        print("Error:", e)
        return None


if __name__ == "__main__":
    conn = get_connection()
    if conn:
        conn.close()
