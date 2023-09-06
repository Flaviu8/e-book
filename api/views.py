from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer,RegisterSerializer,LoginSerializer
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from rest_framework import generics
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token

# Class based view to Get User Details using Token Authentication
class UserDetailAPI(APIView):
  authentication_classes = (TokenAuthentication,)
  permission_classes = (AllowAny,)
  def get(self,request,*args,**kwargs):
    user = User.objects.get(id=request.user.id)
    serializer = UserSerializer(user)
    return Response(serializer.data)

#Class based view to register user
class RegisterUserAPIView(generics.CreateAPIView):
  permission_classes = (AllowAny,)
  serializer_class = RegisterSerializer

class LoginAPIView(APIView):
  authentication_classes = (TokenAuthentication,)
  permission_classes = (AllowAny,)

  def post(self, request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = authenticate(username=serializer.data['username'], password=serializer.data['password'])
    if user is not None:
       token = Token.objects.get_or_create(user=user)
       if isinstance(token, tuple):
        token = Token.objects.get(user=user)
        return Response({'token': token.key})
    else:
      return Response({'error': 'Invalid username or password'})

 