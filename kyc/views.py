import json
import hmac
import hashlib
from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from datetime import datetime, timedelta
from .serializers import SessionDetailsSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User





from .models import UserDetails, SessionDetails
from .utils.didit_client import create_session, retrieve_session


def kyc_test(request):
    # Lee el token desde el archivo .env (a través de settings)
    token = settings.JWT_TOKEN
    print("JWT_TOKEN:", token)
    context = {
        "jwt_token": settings.JWT_TOKEN  # Este es el token constante definido en tu .env
    }
    return render(request, "kyc/test.html", context)

class DiditKYCAPIView(APIView):
    """
    POST /kyc/api/kyc/
    Creates a new KYC session in Didit and stores it locally.
    """
    def post(self, request):
        data = request.data
        print("🔹 Received data:", data)

        # Validate required fields
        if not data.get("first_name") or not data.get("last_name") or not data.get("document_id"):
            return Response(
                {"error": "Missing fields 'first_name', 'last_name', or 'document_id'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        document_id = data["document_id"]
        features = data.get("features", "OCR")
        vendor_data = data.get("vendor_data", data["document_id"])
        callback_url = f"{settings.FRONTEND_URL}/user-validation/{vendor_data}"

        # Check if user exists
        existing_user = UserDetails.objects.filter(document_id=document_id).first()
        
        if existing_user:
            return self.handle_existing_user(existing_user, data, features, callback_url, vendor_data)
        else:
            return self.create_new_user_session(data, features, callback_url, vendor_data)

    def handle_existing_user(self, existing_user, data, features, callback_url, vendor_data):
        """Handle cases when a user with the document_id already exists"""
        
        # Get the latest session for this user
        latest_session = SessionDetails.objects.filter(personal_data=existing_user).order_by('-created_at').first()
        
        if not latest_session:
            # User exists but has no session (unusual case) - create new session
            return self.create_session_for_existing_user(existing_user, features, callback_url, vendor_data)
            
        # Handle based on the latest session status
        session_status = latest_session.status.lower() if latest_session.status else "unknown"
        
        if session_status == "approved":
            # User already verified - return conflict
            return Response(
                {
                    "error": "Ese usuario ya está registrado y tiene una sesión aprobada.",
                    "message": f"User with document_id {existing_user.document_id} already exists and has an approved session.",
                    "user_id": existing_user.id
                },
                status=status.HTTP_409_CONFLICT
            )
        
        elif session_status == "pending" or session_status == "in_progress" or session_status == "in_review":
            # Session is still active - return existing session info
            return Response(
                {
                    "message": "User already has an active verification session",
                    "session_id": latest_session.session_id,
                    "status": latest_session.status,
                    "verification_url": latest_session.verification_url,
                    "user_id": existing_user.id
                },
                status=status.HTTP_200_OK
            )
        
        elif session_status in ["expired", "declined", "abandoned", "kyc_expired"]:
            # Create a new session for the existing user
            return self.create_session_for_existing_user(existing_user, features, callback_url, vendor_data)
            
        else:
            # Unknown status - create new session to be safe
            return self.create_session_for_existing_user(existing_user, features, callback_url, vendor_data)
    
    def create_session_for_existing_user(self, existing_user, features, callback_url, vendor_data):
        """Create a new session for an existing user"""
        
        # Create new session details
        session_details = SessionDetails.objects.create(
            personal_data=existing_user,
            status="pending"
        )
        
        try:
            # Create session in Didit
            session_data = create_session(features, callback_url, vendor_data)
            print("🔹 create_session response:", session_data)
            
            # Update the session details
            session_details.session_id = session_data["session_id"]
            session_details.save()
            
            # Create response
            response_data = {
                "message": "New KYC session created for existing user",
                "session_id": session_data["session_id"],
                "verification_url": session_data["url"],
                "user_id": existing_user.id,
                "expires_at": session_data.get(
                    "expires_at",
                    (datetime.now() + timedelta(days=7)).isoformat()
                )
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            print(f"❌ Error creating session for existing user: {str(e)}")
            session_details.delete()
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def create_new_user_session(self, data, features, callback_url, vendor_data):
        """Create a new user and session"""
        
        # Create new personal data
        personal_data = UserDetails.objects.create(
            first_name=data["first_name"],
            last_name=data["last_name"],
            document_id=data["document_id"]
        )
        
        # Create new session details
        session_details = SessionDetails.objects.create(
            personal_data=personal_data,
            status="pending"
        )
        
        try:
            # Create session in Didit
            session_data = create_session(features, callback_url, vendor_data)
            print("🔹 create_session response:", session_data)
            
            # Update the session details
            session_details.session_id = session_data["session_id"]
            session_details.verification_url = session_data["url"]
            session_details.save()
            
            # Create response
            response_data = {
                "message": "KYC session created successfully",
                "session_id": session_data["session_id"],
                "verification_url": session_data["url"],
                "expires_at": session_data.get(
                    "expires_at",
                    (datetime.now() + timedelta(days=7)).isoformat()
                )
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            print("❌ Error in DiditKYCAPIView:", str(e))
            # Clean up created data
            session_details.delete()
            personal_data.delete()
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
@csrf_exempt
def didit_webhook(request):
    """
    POST /kyc/api/webhook/
    Endpoint to receive status updates from Didit.
    """
    print("✅ Webhook received!")
    print(f"Method: {request.method}")
    print(f"Request: {request}")
    

       
    
    # Para solicitudes POST, procesar el JSON como antes
    if request.method == "POST":
        try:
            print(f"Received data: {request.body.decode('utf-8')}")
            data = json.loads(request.body)
            
            # Extract main data
            session_id = data.get("session_id") or data.get("id")
            didit_status = data.get("status")

            if not session_id or not didit_status:
                return JsonResponse({"error": "Incomplete data (session_id/id, status)"}, status=400)

            session_details = get_object_or_404(SessionDetails, session_id=session_id)
                
            # Update the status
            session_details.status = didit_status.lower()
            
           
            
            # If the status is "completed", get the complete decision
            if didit_status.upper() == "COMPLETED":
                try:
                    decision_data = retrieve_session(session_id)
                    print(f"✅ Decision data retrieved for session {session_id}")
                except Exception as e:
                    print(f"⚠️ Error retrieving complete decision: {str(e)}")
                    # Don't fail the webhook if this fails
            
            session_details.save()
            print(f"✅ Webhook processed: Session {session_id}, Status: {didit_status}")

            return JsonResponse({
                "message": "Webhook processed", 
                "status": didit_status,
                "session_id": session_id
            })
        except Exception as e:
            print(f"❌ Error processing webhook: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Method not allowed"}, status=405)
    

class RetrieveSessionAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, document_id):
        try:
            session_details = get_object_or_404(
                SessionDetails,
                personal_data__document_id=document_id
            )
            session_id = session_details.session_id
            data = retrieve_session(session_id)
            return Response(
                {"session_id": session_id, "data": data},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class GetServiceToken(APIView):
    permission_classes = [AllowAny]
    def get(self, request):

        
        # Create or get service account
        user, created = User.objects.get_or_create(
            username='service_account',
            defaults={'is_active': True}
        )
        
        refresh = RefreshToken.for_user(user)
        
        # Return the token with timestamp
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        })
    
def validate_and_update_user_details(user_details, kyc_data):
    """
    Valida y actualiza los detalles del usuario con los datos de KYC.
    """
    document_id = kyc_data.get("personal_number") or kyc_data.get("document_number")
    first_name = kyc_data.get("first_name", "Unknown")
    last_name = kyc_data.get("last_name", "")
    document_type = kyc_data.get("document_type", "unknown")
    date_of_birth = kyc_data.get("date_of_birth")
    nationality = kyc_data.get("issuing_state_name")

    if document_id:
        user_details.document_id = document_id
    if first_name:
        user_details.first_name = first_name
    if last_name:
        user_details.last_name = last_name
    if document_type:
        user_details.document_type = document_type
    if date_of_birth:
        user_details.date_of_birth = date_of_birth
    if nationality:
        user_details.nationality = nationality

    user_details.save()
    return user_details


def check_duplicate_document_id(document_id, session_details):
    """
    Verifica si el document_id ya existe en otro usuario y elimina la sesión y el usuario si es necesario.
    """
    existing_user = UserDetails.objects.filter(document_id=document_id).exclude(id=session_details.personal_data.id).first()
    if existing_user:
        # Eliminar la sesión y el usuario relacionados con el session_id
        session_details.personal_data.delete()
        session_details.delete()
       
        print(f"❌ Duplicate document_id found. Deleted session and user related to session_id: {session_details.session_id}")
        return True
    return False
  
class ResolveSessionAPIView(APIView):
    """
    DELETE /kyc/api/session/<session_id>/resolve/
    Resolve a session 
    """


    def delete(self, request, session_id):
        try:
            # Find the session
            session = get_object_or_404(SessionDetails, session_id=session_id)
            
            # Get reference to the personal data before we modify anything
            user_details = session.personal_data
            
            # Update session status to rejected
            session.status = "rejected"
            session.save()
            
            # Delete the user's personal data
            if user_details:
                user_details.delete()
                
            return Response({
                "message": "Session rejected and user data deleted successfully",
                "session_id": session_id
            }, status=status.HTTP_200_OK)
            
        except SessionDetails.DoesNotExist:
            return Response({
                "error": f"Session with ID {session_id} not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"❌ Error rejecting session: {str(e)}")
            return Response({
                "error": f"Failed to reject session: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

    def patch(self, request, session_id):
        try:
            # Recuperar la sesión de Didit y los detalles locales
            didit_session = retrieve_session(session_id)
            session_details = get_object_or_404(SessionDetails, session_id=session_id)
            kyc_data = didit_session.get("kyc", {})

            if not kyc_data:
                return Response({"error": "No KYC data found in session"}, status=status.HTTP_400_BAD_REQUEST)

            # Extraer el document_id del KYC
            document_id = kyc_data.get("personal_number") or kyc_data.get("document_number")
            if not document_id:
                return Response({"error": "Missing document ID in KYC data"}, status=status.HTTP_400_BAD_REQUEST)

            # Verificar si el document_id ya existe en otro usuario
            if check_duplicate_document_id(document_id, session_details):
                return Response({"error": "Duplicate document_id found. Session and user deleted."}, status=status.HTTP_400_BAD_REQUEST)

            # Actualizar o crear los detalles del usuario
            if not session_details.personal_data:
                user_details = UserDetails.objects.create(
                    first_name=kyc_data.get("first_name", "Unknown"),
                    last_name=kyc_data.get("last_name", ""),
                    document_id=document_id,
                    document_type=kyc_data.get("document_type", "unknown"),
                    date_of_birth=kyc_data.get("date_of_birth"),
                    nationality=kyc_data.get("issuing_state_name"),
                )
                session_details.personal_data = user_details
                session_details.save()
                print(f"Created new UserDetails with ID {user_details.id} for session {session_id}")
            else:
                user_details = session_details.personal_data
                validate_and_update_user_details(user_details, kyc_data)
                print(f"Updated UserDetails with ID {user_details.id} for session {session_id}")

            # Actualizar el estado de la sesión
            status_from_didit = kyc_data.get("status") or didit_session.get("status")
            if status_from_didit:
                session_details.status = status_from_didit.lower()
                session_details.save()
                print(f"Updated SessionDetails status: {session_details.status}")

            # Serializar y devolver los detalles de la sesión
            serializer = SessionDetailsSerializer(session_details)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"❌ Error updating session data: {str(e)}")
            return Response({"error": f"Failed to update session: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
