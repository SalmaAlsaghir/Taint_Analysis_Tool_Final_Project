from django.http import HttpResponse

def vulnerable_xss_view(request):
    user_input = request.GET.get('message')
    response = HttpResponse(f"User message: {user_input}")  #vulnerable to XSS
    return response
