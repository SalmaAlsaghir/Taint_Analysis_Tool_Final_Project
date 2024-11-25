from django.http import HttpResponse
import sqlite3

def indirect_taint_view(request):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    user_input = request.GET.get('data')
    intermediate_var = user_input
    final_var = intermediate_var
    query = f"SELECT * FROM info WHERE data = '{final_var}'"
    cursor.execute(query)  #vulnerable due to indirect tainting
    results = cursor.fetchall()
    return HttpResponse(f"Results: {results}")
