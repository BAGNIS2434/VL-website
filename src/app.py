from flask_migrate import Migrate
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from .config import Config
  # Fix the import path
from .models.user import db, User  # Fix the import path
from .models.video import Video, Annotation
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, unset_jwt_cookies
)
from flask_mail import Mail, Message
import os
import secrets
from datetime import datetime, timedelta
import re
from werkzeug.utils import secure_filename

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Production settings
    if not app.debug:  # Check debug mode instead of ENV
        app.config.update({
            'JWT_COOKIE_SECURE': True,
            'SESSION_COOKIE_SECURE': True,
            'SESSION_COOKIE_HTTPONLY': True,
            'PREFERRED_URL_SCHEME': 'https'
        })
    
    # Create uploads directory
    uploads_dir = os.path.join(app.static_folder, 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)

    # Make sure uploads directory is writable
    os.chmod(uploads_dir, 0o755)
    
    # Initialize database and migrations
    db.init_app(app)
    migrate = Migrate(app, db)
    jwt = JWTManager(app)
    mail = Mail(app)
    
    # Update JWT configuration
    app.config.update({
        'JWT_TOKEN_LOCATION': ['cookies'],
        'JWT_COOKIE_CSRF_PROTECT': False,
        'JWT_ACCESS_COOKIE_NAME': 'access_token_cookie',
        'JWT_REFRESH_COOKIE_NAME': 'refresh_token_cookie',
        'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=24),
        'JWT_COOKIE_SECURE': False,  # Set to True in production
        'JWT_ACCESS_COOKIE_PATH': '/',
        'JWT_COOKIE_SAMESITE': 'Lax'
    })

    # Recreate all tables
    with app.app_context():
        try:
            # Drop all tables and recreate
            db.drop_all()
            db.create_all()
            print("Database tables recreated successfully!")
        except Exception as e:
            print(f"Error recreating database tables: {e}")

    app.url_map.strict_slashes = False

    @jwt.unauthorized_loader
    def unauthorized_callback(callback):
        return redirect(url_for('login_page'))

    @jwt.invalid_token_loader
    def invalid_token_callback(callback):
        response = redirect(url_for('login_page'))
        unset_jwt_cookies(response)
        return response

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        response = redirect(url_for('login_page'))
        unset_jwt_cookies(response)
        return response

    @app.route('/')
    def index():
        videos = Video.get_all_videos()
        return render_template('home.html', videos=videos)

    @app.route('/home')
    def home():
        videos = Video.get_all_videos()
        return render_template('home.html', videos=videos)

    @app.route('/upload', methods=['GET'])
    @jwt_required()
    def upload():
        return render_template('upload.html')

    @app.route('/login/', methods=['GET', 'POST'])
    def login_page():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                # Create access token
                access_token = create_access_token(identity=user.id)
                # Create response with redirect to profile instead of index
                resp = redirect(url_for('profile'))
                # Set cookie with proper configuration
                resp.set_cookie(
                    'access_token_cookie',
                    access_token,
                    httponly=True,
                    secure=False,  # Set to True in production
                    samesite='Lax',
                    path='/',
                    max_age=86400  # 24 hours
                )
                return resp
            return render_template('login.html', error="Invalid username or password")
        return render_template('login.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup_page():
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            name = request.form.get('name')
            if User.query.filter_by(username=username).first():
                return render_template('signup.html', error="Username already exists")
            if User.query.filter_by(email=email).first():
                return render_template('signup.html', error="Email already exists")
            user = User(username=username, email=email, name=name)
            user.set_password(password)
            try:
                db.session.add(user)
                db.session.commit()
                # Create access token with simple user ID
                access_token = create_access_token(identity=str(user.id))
                # Change redirect to profile page instead of index
                resp = redirect(url_for('profile'))
                resp.set_cookie('access_token_cookie', access_token, httponly=True, secure=False, samesite='Lax', max_age=86400)
                return resp
            except Exception as e:
                db.session.rollback()
                return render_template('signup.html', error="Registration failed")
        return render_template('signup.html')

    @app.route('/dashboard/', methods=['GET', 'POST'])
    @jwt_required()
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/profile/')
    @jwt_required()
    def profile():
        try:
            user_id = get_jwt_identity()
            if not user_id:
                raise ValueError("No user ID in token")
            user = db.session.get(User, int(user_id))
            if not user:
                raise ValueError("User not found")
            user_videos = Video.get_user_videos(user_id)
            return render_template('profile.html', 
                                user=user, 
                                user_videos=user_videos)
                                
        except Exception as e:
            print(f"Profile error: {str(e)}")
            response = redirect(url_for('login_page'))
            unset_jwt_cookies(response)
            return response

    @app.route('/settings/', methods=['GET', 'POST'])
    @jwt_required()
    def settings():
        return render_template('settings.html')

    @app.route('/networking/', methods=['GET', 'POST'])
    @jwt_required()
    def networking():
        return render_template('networking-page.html')

    @app.route('/forgot-password/', methods=['GET', 'POST'])
    def forgot_password_page():
        if request.method == 'POST':
            email = request.form.get('email')
            if not email:
                flash('Email is required', 'error')
                return render_template('forgot-password.html')
            user = User.query.filter_by(email=email).first()
            if user:
                try:
                    reset_token = secrets.token_urlsafe(32)
                    user.reset_token = reset_token
                    user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
                    db.session.commit()
                    reset_url = url_for('reset_password', token=reset_token, _external=True)
                    msg = Message('Password Reset Request',
                                sender=app.config['MAIL_DEFAULT_SENDER'],
                                recipients=[user.email])
                    msg.body = f'''To reset your password, visit the following link:
{reset_url}
                    
If you did not make this request, please ignore this email.
'''
                    mail.send(msg)
                    flash('Password reset link has been sent to your email', 'success')
                except Exception as e:
                    print(f"Reset password error: {str(e)}")
                    db.session.rollback()
                    flash('Failed to send reset email. Please try again later.', 'error')
            else:
                # Don't reveal if email exists
                flash('If an account exists with this email, a reset link will be sent', 'info')
            return redirect(url_for('login_page'))
        return render_template('forgot-password.html')

    @app.route('/sessions/', methods=['GET', 'POST'])
    @jwt_required()
    def sessions():
        return render_template('sessions.html')
            
    @app.route('/stream/<int:video_id>')
    @jwt_required()
    def stream(video_id):
        try:
            user_id = get_jwt_identity()
            video = Video.query.get_or_404(video_id)
            annotations = Annotation.query.filter_by(video_id=video_id).all()
            # Convert video and annotations to dict for JSON serialization
            video_dict = video.to_dict()
            annotations_list = [ann.to_dict() for ann in annotations]
            return render_template('stream.html', 
                                video=video_dict,
                                annotations=annotations_list,
                                user_id=user_id)
        except Exception as e:
            print(f"Stream error: {str(e)}")
            flash('Error loading video', 'error')
            return redirect(url_for('index'))

    # Store revoked tokens in memory
    revoked_tokens = set()

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        return jti in revoked_tokens

    @app.route('/api/auth/register', methods=['POST'])
    def register():
        data = request.get_json()
        required_fields = ['username', 'email', 'password']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing fields: {", ".join(missing_fields)}'}), 400
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 409
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 409
        user = User(
            username=data['username'],
            email=data['email']
        )
        user.set_password(data['password'])
        try:
            db.session.add(user)
            db.session.commit()
            return jsonify({
                'message': 'User created successfully',
                'user': user.to_dict()
            }), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Failed to create user'}), 500

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.get_json()
        if not all(k in data for k in ['username', 'password']):
            return jsonify({'error': 'Missing username or password'}), 400
        user = User.query.filter_by(username=data['username']).first()
        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid username or password'}), 401
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }), 200

    @app.route('/api/protected', methods=['GET'])
    @jwt_required()
    def protected():
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({
            'message': 'Access granted to protected route',
            'user': user.to_dict()
        })

    @app.route('/api/auth/refresh', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh():
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return jsonify({'access_token': access_token}), 200

    @app.route('/api/auth/logout', methods=['POST'])
    @jwt_required(verify_type=False)  # Don't verify token type for logout
    def logout():
        resp = jsonify({"message": "Successfully logged out"})
        unset_jwt_cookies(resp)  # Remove all JWT cookies
        return resp, 200

    @app.route('/api/videos/create', methods=['POST'])
    @jwt_required()
    def create_video():
        try:
            data = request.get_json()
            user_id = get_jwt_identity()
            
            if not data or not user_id:
                return jsonify({'error': 'Invalid request'}), 401
            
            video = Video(
                title=data['title'],
                youtube_id=data['youtube_id'],
                description=data.get('description', ''),
                user_id=int(user_id)
            )
            
            db.session.add(video)
            db.session.commit()
            # Return newly created video data
            return jsonify({
                'message': 'Video created successfully',
                'id': video.id,
                'title': video.title
            }), 201
            
        except Exception as e:
            print(f"Video creation error: {str(e)}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/videos/<int:video_id>', methods=['PUT'])
    @jwt_required()
    def update_video(video_id):
        try:
            user_id = get_jwt_identity()
            video = Video.query.get_or_404(video_id)
            
            # Check if user owns the video
            if video.user_id != int(user_id):
                return jsonify({'error': 'Unauthorized'}), 403
            
            data = request.get_json()
            if 'title' in data:
                video.title = data['title']
            if 'description' in data:
                video.description = data['description']
            
            db.session.commit()
            return jsonify(video.to_dict()), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating video: {str(e)}")
            return jsonify({'error': 'Failed to update video'}), 500

    @app.route('/api/annotations/create', methods=['POST'])
    @jwt_required()
    def create_annotation():
        try:
            data = request.get_json()
            user_id = get_jwt_identity()
            
            # Validate required fields
            if not all(key in data for key in ['content', 'timestamp', 'videoId']):
                return jsonify({'error': 'Missing required fields'}), 400
            
            # Validate timestamp format
            timestamp = data['timestamp']
            if not re.match(r'^(?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d)$', timestamp):
                return jsonify({'error': 'Invalid timestamp format'}), 400
            
            # Check video exists
            video = Video.query.get(data['videoId'])
            if not video:
                return jsonify({'error': 'Video not found'}), 404
            
            annotation = Annotation(
                content=data['content'],
                timestamp=timestamp,
                video_id=data['videoId'],
                user_id=user_id
            )
            
            db.session.add(annotation)
            db.session.commit()
            return jsonify({
                'message': 'Annotation created successfully',
                **annotation.to_dict()
            }), 201
        except Exception as e:
            db.session.rollback()
            print(f"Error creating annotation: {str(e)}")
            return jsonify({'error': 'Failed to create annotation'}), 500

    @app.route('/api/annotations/<int:annotation_id>', methods=['DELETE'])
    @jwt_required()
    def delete_annotation(annotation_id):
        try:
            user_id = get_jwt_identity()
            annotation = Annotation.query.get_or_404(annotation_id)
            
            # Check if user owns the annotation
            if annotation.user_id != int(user_id):
                return jsonify({'error': 'Unauthorized'}), 403
            
            db.session.delete(annotation)
            db.session.commit()
            
            return jsonify({'message': 'Annotation deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting annotation: {str(e)}")
            return jsonify({'error': 'Failed to delete annotation'}), 500
            
    @app.route('/api/annotations/<int:annotation_id>', methods=['PUT'])
    @jwt_required()
    def update_annotation(annotation_id):
        try:
            user_id = get_jwt_identity()
            data = request.get_json()
            
            if 'content' not in data:
                return jsonify({'error': 'Content is required'}), 400
            
            annotation = Annotation.query.get_or_404(annotation_id)
            # Check if user owns the annotation
            if annotation.user_id != int(user_id):
                return jsonify({'error': 'Unauthorized'}), 403
            
            # Update content
            annotation.content = data['content']
            
            # Update timestamp if provided
            if 'timestamp' in data:
                if not re.match(r'^(?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d)$', data['timestamp']):
                    return jsonify({'error': 'Invalid timestamp format'}), 400
                annotation.timestamp = data['timestamp']
            
            db.session.commit()
            return jsonify({
                'message': 'Annotation updated successfully',
                **annotation.to_dict()
            }), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error updating annotation: {str(e)}")
            return jsonify({'error': 'Failed to update annotation'}), 500

    @app.route('/api/videos/list', methods=['POST'])
    def list_videos():
        try:
            data = request.get_json()
            video_id = data.get('videoId')
            if video_id:
                videos = Video.query.filter_by(id=video_id).all()
            else:
                videos = Video.query.all()
            return jsonify([video.to_dict() for video in videos]), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/videos/<int:video_id>', methods=['DELETE'])
    @jwt_required()
    def delete_video(video_id):
        try:
            user_id = get_jwt_identity()
            video = Video.query.get_or_404(video_id)
            
            # Check if user owns the video
            if video.user_id != int(user_id):
                return jsonify({'error': 'Unauthorized'}), 403
            
            db.session.delete(video)
            db.session.commit()
            
            return jsonify({'message': 'Video deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting video: {str(e)}")
            return jsonify({'error': 'Failed to delete video'}), 500

    @app.route('/api/annotations/list', methods=['POST'])
    def list_annotations():
        try:    
            data = request.get_json()
            video_id = data.get('videoId')
            annotations = Annotation.query.filter_by(video_id=video_id).all()
            return jsonify([ann.to_dict() for ann in annotations]), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/update_profile', methods=['POST'])
    @jwt_required()
    def update_profile():
        current_user_id = int(get_jwt_identity())  # Convert string back to integer
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        data = request.get_json()
        try:
            if 'name' in data:
                user.name = data['name']
            if 'email' in data:
                user.email = data['email']
            db.session.commit()
            return jsonify({'message': 'Profile updated successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/update_profile_picture', methods=['POST'])
    @jwt_required()
    def update_profile_picture():
        try:
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if 'profile_picture' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
            
            file = request.files['profile_picture']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
                
            if not file.content_type.startswith('image/'):
                return jsonify({'error': 'File must be an image'}), 400
                
            # Create uploads directory if it doesn't exist
            uploads_dir = os.path.join(app.static_folder, 'uploads')
            if not os.path.exists(uploads_dir):
                os.makedirs(uploads_dir, exist_ok=True)
                
            # Clean up old profile picture if it exists
            if user.profile_picture:
                old_file = os.path.join(app.static_folder, user.profile_picture.lstrip('/static/'))
                if os.path.exists(old_file):
                    os.remove(old_file)
                
            # Save file with secure filename and timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = secure_filename(f'profile_{user_id}_{timestamp}_{file.filename}')
            filepath = os.path.join(uploads_dir, filename)
            
            # Save the file
            file.save(filepath)
            # Update user profile picture path in database
            user.profile_picture = f'/static/uploads/{filename}'
            db.session.commit()
            return jsonify({
                'message': 'Profile picture updated successfully',
                'profile_picture_url': user.profile_picture
            })
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating profile picture: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/auth/reset-password', methods=['POST'])
    def request_password_reset():
        try:
            data = request.get_json()
            email = data.get('email')
            if not email:
                return jsonify({'error': 'Email is required'}), 400
            user = User.query.filter_by(email=email).first()
            if not user:
                # Don't reveal if email exists
                return jsonify({'message': 'If an account exists with this email, a reset link will be sent'}), 200
            reset_token = secrets.token_urlsafe(32)
            user.reset_token = reset_token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
                            
            try:
                reset_url = url_for('reset_password', token=reset_token, _external=True)
                msg = Message('Password Reset Request',
                            sender=app.config['MAIL_DEFAULT_SENDER'],
                            recipients=[user.email])
                msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.
'''
                # Add debug logging
                print(f"Attempting to send email with config:")
                print(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
                print(f"MAIL_PORT: {app.config['MAIL_PORT']}")
                print(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
                print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
                print(f"MAIL_DEFAULT_SENDER: {app.config['MAIL_DEFAULT_SENDER']}")
                
                mail.send(msg)
                return jsonify({'message': 'Password reset email sent'}), 200
                
            except Exception as mail_error:
                db.session.rollback()
                print(f"Mail error details: {str(mail_error)}")
                return jsonify({'error': 'Failed to send email. Please check mail server configuration.'}), 500
                
        except Exception as e:
            print(f"Reset password error: {str(e)}")
            return jsonify({'error': 'Failed to process reset request'}), 500

    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        user = User.query.filter_by(reset_token=token).first()
        
        if not user or not user.reset_token_expires or user.reset_token_expires < datetime.utcnow():
            flash('Invalid or expired reset token. Please try again.', 'error')
            return redirect(url_for('forgot_password_page'))

        if request.method == 'POST':
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            if not password or not confirm_password:
                flash('Both password fields are required', 'error')
                return render_template('reset-password.html', token=token)
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('reset-password.html', token=token)

            try:
                user.set_password(password)
                user.reset_token = None
                user.reset_token_expires = None
                db.session.commit()
                flash('Your password has been updated!', 'success')
                return redirect(url_for('login_page'))
            except Exception as e:
                db.session.rollback()
                flash('Failed to update password. Please try again.', 'error')
                return render_template('reset-password.html', token=token)

        return render_template('reset-password.html', token=token)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
