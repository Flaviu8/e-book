from rest_framework.response import Response
from .serializers import UserSerializer, RegisterSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.http import JsonResponse
from rest_framework.status import HTTP_400_BAD_REQUEST
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication



# Class based view to Get User Details using Token Authentication
class UserDetailAPI(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)  # Only allow authenticated users

    def get(self, request,):
        user = request.user
        serializer = UserSerializer(user)
        user_data = serializer.data
        user_data['authenticated'] = True
        user_data['user_id'] = user.id
        user_data['username'] = user.username
        return Response({'user': user_data})
    
# class UserDetailAPI(APIView):
#     permission_classes = (IsAuthenticated,)

#     def get(self, request):
#         permission_classes = (IsAuthenticated,)
#         # Check if the user is authenticated
#         if permission_classes:
#             user = request.user
#             user_data = user.to_dict()
#         else:
#             user_data = {}

#         return Response(user_data)

    

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
    

            # Set the JWT as an HttpOnly cookie
            response = JsonResponse({'message': 'Login successful'})
            response.set_cookie(key='jwt_token', value=access_token, httponly=True, secure=True)

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
 