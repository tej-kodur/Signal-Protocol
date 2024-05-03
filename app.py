from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import os
from crypto import create_shared_key,DoubleRatchet

app = Flask(__name__)
app = Flask(__name__, static_url_path='/static')

# Initialize the database
def init_db():
    with sqlite3.connect("app.db") as conn:
        conn.execute("""
            DROP TABLE IF EXISTS messages;
            """)
        conn.execute("""
            DROP TABLE IF EXISTS unique_pairs;
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                recipient TEXT,
                message BLOB,
                tag BLOB
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS unique_pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                recipient TEXT,
                key BLOB
            );
        """)

# Route for the landing page
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        return redirect(url_for('message', username=username))
    return render_template('index.html')


@app.route('/clear_messages/<username>', methods=['GET'])
def clear_messages(username):
    with sqlite3.connect("app.db") as conn:
        cursor = conn.cursor()
        # Assuming you want to clear messages where 'username' is the recipient
        cursor.execute("DELETE FROM messages WHERE recipient = ?", (username,))
        conn.commit()
    return redirect(url_for('message', username=username))


@app.route('/message/<username>', methods=['GET', 'POST'])
def message(username):
    messages = []
    if 'view' in request.args:  # Check if the 'view' query parameter is present
        with sqlite3.connect("app.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username,message,tag FROM messages WHERE recipient = ?", (username,))
            rows = cursor.fetchall()
            messages = []
            for i in rows:
                sender = i[0]
                receiver = username
                cursor.execute("SELECT * FROM unique_pairs WHERE sender = ? AND recipient = ?", (sender, receiver))
                row = cursor.fetchone()
                shared_key = row[3]
                ratchet = DoubleRatchet(shared_key)
                print("Decrypting messages using double ratchet..")
                messages.append([i[0],ratchet.decrypt(i[2], i[1]).decode(),i[1]])

    if request.method == 'POST':
        recipient = request.form['recipient']
        message = request.form['message']
        with sqlite3.connect("app.db") as conn:
            cursor = conn.cursor()
            # Check if sender-recipient pair exists
            cursor.execute("SELECT * FROM unique_pairs WHERE sender = ? AND recipient = ?", (username, recipient))
            row = cursor.fetchone()
            shared_key = ''
            if not row:  # If the pair does not exist, insert it with a new key
                new_key = create_shared_key()  # Generate a simple random key for demonstration
                cursor.execute("INSERT INTO unique_pairs (sender, recipient, key) VALUES (?, ?, ?)",
                               (username, recipient, new_key))
                print("Created a new shared secret using X3DH for users {} and {}".format(username,recipient))
                shared_key = new_key
            else:
                #print(row)
                shared_key = row[3]
            #print(shared_key)
            # Insert the message as usual
            ratchet = DoubleRatchet(shared_key)
            tag,encrypted_msg = ratchet.encrypt(message)
            
            conn.execute("INSERT INTO messages (username, recipient, message,tag) VALUES (?, ?, ?, ?)",
                         (username, recipient, encrypted_msg,tag))
            conn.commit()
        return redirect(url_for('message', username=username, view='true'))  # Optionally auto-load messages after sending

    return render_template('message.html', username=username, messages=messages)


@app.route('/success')
def success():
    return "Message sent successfully!"

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
