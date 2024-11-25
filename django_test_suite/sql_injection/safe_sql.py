# safe_sql.py

from django.http import HttpResponse
import sqlite3

def safe_sql_view(request):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    user_input = request.GET.get('username')
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (user_input,))  # Safe parameterized query
    results = cursor.fetchall()
    return HttpResponse(f"User data: {results}")
