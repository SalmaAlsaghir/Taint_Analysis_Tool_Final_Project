from django.http import HttpResponse
from django.shortcuts import render
from django.db import connection
import os
import pickle

def vulnerable_view(request):
    user_input = request.GET.get('input', '')

    #SQL Injection
    with connection.cursor() as cursor:
        query = "SELECT * FROM users WHERE username = '%s'" % user_input
        cursor.execute(query)
        results = cursor.fetchall()

    #XSS
    response = HttpResponse("Welcome %s" % user_input)

    #command Injection
    os.system('echo %s' % user_input)

    #insecure Deserialization
    data = pickle.loads(user_input)

    return response
