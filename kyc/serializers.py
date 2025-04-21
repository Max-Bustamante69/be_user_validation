from rest_framework import serializers
from .models import SessionDetails, UserDetails

class UserDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDetails
        fields = ['id', 'first_name', 'last_name', 'document_id', 'document_type', 'nationality', 'date_of_birth']

class SessionDetailsSerializer(serializers.ModelSerializer):
    personal_data = UserDetailsSerializer(read_only=True)
    
    class Meta:
        model = SessionDetails
        fields = ['personal_data', 'session_id', 'status']
        
        #https://verify.didit.me/session/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3NDM2MjIyNTcsImV4cCI6MTc0NDIyNzA1Nywic2Vzc2lvbl9pZCI6ImUzM2EzZjkyLTI2M2MtNGUyNy1iZTczLWZlYzg0MTE5NDc4ZCJ9.9yKcm_PKZmd0pc7cQ_Zz7h5B1ick_CmVKcqzlNH74g0?step=start