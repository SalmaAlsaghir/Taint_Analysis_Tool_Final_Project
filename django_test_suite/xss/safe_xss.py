# safe_xss.py

from django.http import HttpResponse
from django.utils.html import escape

def safe_xss_view(request):
    user_input = request.GET.get('message')
    sanitized_input = escape(user_input)
    response = HttpResponse(f"User message: {sanitized_input}")  # Safe output
    return response
