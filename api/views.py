from rest_framework.response import Response
from .serializers import RegisterSerializer, UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny
from django.http import JsonResponse
from rest_framework.status import HTTP_400_BAD_REQUEST
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
import jwt
from django.contrib.auth.models import User
from django.conf import settings




#Class based view to register user
class RegisterUserAPIView(generics.CreateAPIView):
  permission_classes = (AllowAny,)
  serializer_class = RegisterSerializer

class LoginAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            response = Response()    

            # Set the JWT as an HttpOnly cookie
            response = JsonResponse({'message': 'Login successful'})
            response.set_cookie(key='jwt_token', value=access_token, httponly=True, secure=True)
            response.data = {
                'jwt_cookie' : access_token
            }

            return response
        else:
            return JsonResponse({'error': 'Invalid username or password'}, status=HTTP_400_BAD_REQUEST)
        
class LogoutAPIView(APIView): 
    permission_classes = (AllowAny,)
    def post(self, request):
        # Clear the JWT token cookie by setting an empty value and Max-Age to 0 seconds (expires immediately)
        response = JsonResponse({'message': 'Logout successful'})
        response.set_cookie(key='jwt_token', value='', httponly=True, max_age=0, secure=True)
        return response
    

class UserDetailAPI(APIView):
    def get(self, request):
        # Retrieve the JWT token from cookies
        jwt_token = request.COOKIES.get("jwt_token")

        if not jwt_token:
            raise AuthenticationFailed('Unauthenticated')

        try:
            # Verify and decode the JWT token
            payload = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated')

        # Retrieve the user based on the user ID from the JWT payload
        user = User.objects.filter(id=payload['user_id']).first()

        if not user:
            raise AuthenticationFailed('User not found')

        # Serialize the user data
        serializer = UserSerializer(user)

        return Response(serializer.data)