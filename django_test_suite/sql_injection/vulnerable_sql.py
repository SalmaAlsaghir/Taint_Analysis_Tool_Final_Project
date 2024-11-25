from django.http import HttpResponse
import sqlite3

def vulnerable_sql_view(request):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    user_input = request.GET.get('username')
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)  #vulnerable to SQL Injection
    results = cursor.fetchall()
    return HttpResponse(f"User data: {results}")
