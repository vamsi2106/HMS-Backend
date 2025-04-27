import sqlite3

# Connect to the SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('hotel.db')
cursor = conn.cursor()

# Read the schema file and execute it
with open('schema.sql', 'r') as f:
    cursor.executescript(f.read())

# Commit changes and close the connection
conn.commit()
conn.close()

print("Database initialized successfully!")