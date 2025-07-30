#!/usr/bin/env python3
"""
Flask Media Manager with Jellyfin Integration
A lightweight web application for uploading and managing media files
that integrates directly with Jellyfin's media directories.
Now with full nested folder support!
"""

import os
import json
import hashlib
import mimetypes
import subprocess
import re
from datetime import datetime
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from PIL import Image, ImageOps
import requests

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this'
    UPLOAD_FOLDER = '/mnt/media'
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024 * 1024  # 10GB max file size
    ALLOWED_EXTENSIONS = {
        'image': {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'},
        'video': {'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4v'},
        'audio': {'mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a', 'wma'}
    }
    JELLYFIN_URL = os.environ.get('JELLYFIN_URL', 'http://localhost:8096')
    JELLYFIN_API_KEY = os.environ.get('JELLYFIN_API_KEY', '')
    THUMBNAIL_SIZE = (300, 300)
    USERS_FILE = 'users.json'
    
    # File size limits by type (in bytes)
    FILE_SIZE_LIMITS = {
        'image': 100 * 1024 * 1024,      # 100MB for images
        'video': 10 * 1024 * 1024 * 1024, # 10GB for videos
        'audio': 500 * 1024 * 1024       # 500MB for audio
    }

# Flask app setup
app = Flask(__name__)
app.config.from_object(Config)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# User model
class User(UserMixin):
    def __init__(self, id, username, password_hash, is_admin=False):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin

# User management
class UserManager:
    def __init__(self, users_file):
        self.users_file = users_file
        self.users = self.load_users()

    def load_users(self):
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    data = json.load(f)
                    return {
                        user_id: User(
                            user_id, 
                            user_data['username'], 
                            user_data['password_hash'],
                            user_data.get('is_admin', False)
                        )
                        for user_id, user_data in data.items()
                    }
            except (json.JSONDecodeError, KeyError):
                pass
        return {}

    def save_users(self):
        data = {
            user_id: {
                'username': user.username,
                'password_hash': user.password_hash,
                'is_admin': user.is_admin
            }
            for user_id, user in self.users.items()
        }
        with open(self.users_file, 'w') as f:
            json.dump(data, f, indent=2)

    def create_user(self, username, password, is_admin=False):
        user_id = str(len(self.users) + 1)
        password_hash = generate_password_hash(password)
        user = User(user_id, username, password_hash, is_admin)
        self.users[user_id] = user
        self.save_users()
        return user

    def get_user(self, user_id):
        return self.users.get(user_id)

    def get_user_by_username(self, username):
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    def verify_password(self, username, password):
        user = self.get_user_by_username(username)
        if user and check_password_hash(user.password_hash, password):
            return user
        return None

# Initialize user manager
user_manager = UserManager(Config.USERS_FILE)

# Create default admin user if no users exist
if not user_manager.users:
    user_manager.create_user('admin', 'admin123', is_admin=True)
    print("Created default admin user: admin/admin123")

@login_manager.user_loader
def load_user(user_id):
    return user_manager.get_user(user_id)

# Utility functions
def allowed_file(filename):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False, None
    ext = filename.rsplit('.', 1)[1].lower()
    for file_type, extensions in Config.ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return True, file_type
    return False, None

def get_media_path(file_type):
    """Get the appropriate media directory based on file type"""
    paths = {
        'image': os.path.join(Config.UPLOAD_FOLDER, 'Pictures'),
        'video': os.path.join(Config.UPLOAD_FOLDER, 'Movies'),
        'audio': os.path.join(Config.UPLOAD_FOLDER, 'Music')
    }
    return paths.get(file_type, Config.UPLOAD_FOLDER)

def ensure_directory(path):
    """Ensure directory exists"""
    os.makedirs(path, exist_ok=True)

def sanitize_path_component(component):
    """Sanitize a single path component to prevent path traversal"""
    if not component:
        return None
    # Remove any path separators and dangerous chars
    component = component.replace('..', '').replace('/', '').replace('\\', '')
    component = secure_filename(component)
    return component if component else None

def sanitize_folder_path(folder_path):
    """Sanitize a complete folder path (can contain multiple levels)"""
    if not folder_path:
        return ''
    
    # Split by common path separators and sanitize each component
    components = []
    for part in folder_path.replace('\\', '/').split('/'):
        sanitized = sanitize_path_component(part)
        if sanitized:
            components.append(sanitized)
    
    return '/'.join(components)

def get_nested_folder_structure(base_path, max_depth=5):
    """Get nested folder structure for a media directory"""
    def scan_directory(path, relative_path='', current_depth=0):
        folders = []
        if current_depth >= max_depth or not os.path.exists(path):
            return folders
        
        try:
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    relative_item_path = os.path.join(relative_path, item) if relative_path else item
                    folder_info = {
                        'name': item,
                        'path': relative_item_path,
                        'full_path': item_path,
                        'depth': current_depth,
                        'children': scan_directory(item_path, relative_item_path, current_depth + 1)
                    }
                    folders.append(folder_info)
        except (OSError, PermissionError):
            pass
        
        return sorted(folders, key=lambda x: x['name'].lower())
    
    return scan_directory(base_path)

def get_all_folder_paths(base_path, max_depth=5):
    """Get all folder paths as a flat list for dropdowns"""
    def collect_paths(folders, paths=None):
        if paths is None:
            paths = []
        
        for folder in folders:
            paths.append({
                'name': folder['name'],
                'path': folder['path'],
                'display_name': folder['path'].replace('/', ' → '),
                'depth': folder['depth']
            })
            if folder['children']:
                collect_paths(folder['children'], paths)
        
        return paths
    
    nested_structure = get_nested_folder_structure(base_path, max_depth)
    return collect_paths(nested_structure)

def scan_media_files(base_path, folder_path=''):
    """Recursively scan media files in a directory"""
    media_files = []
    scan_path = os.path.join(base_path, folder_path) if folder_path else base_path
    
    if not os.path.exists(scan_path):
        return media_files
    
    try:
        for item in os.listdir(scan_path):
            item_path = os.path.join(scan_path, item)
            relative_path = os.path.join(folder_path, item) if folder_path else item
            
            if os.path.isfile(item_path):
                is_allowed, detected_type = allowed_file(item)
                if is_allowed:
                    file_info = get_file_info(item_path)
                    
                    # Check for thumbnail
                    thumbnail_filename = f"{hashlib.md5(item_path.encode()).hexdigest()}.jpg"
                    thumbnail_path = os.path.join(app.static_folder, 'thumbnails', thumbnail_filename)
                    
                    media_files.append({
                        'filename': item,
                        'relative_path': relative_path,
                        'folder': folder_path,
                        'type': detected_type,
                        'size': file_info['size'],
                        'modified': file_info['modified'],
                        'thumbnail': thumbnail_filename if os.path.exists(thumbnail_path) else None,
                        'full_path': item_path
                    })
            elif os.path.isdir(item_path):
                # Recursively scan subdirectories
                subfolder_files = scan_media_files(base_path, relative_path)
                media_files.extend(subfolder_files)
    except (OSError, PermissionError):
        pass
    
    return media_files

def generate_thumbnail(file_path, file_type, thumbnail_path):
    """Generate thumbnail for media files"""
    try:
        if file_type == 'image':
            with Image.open(file_path) as img:
                img = ImageOps.exif_transpose(img)  # Handle rotation
                img.thumbnail(Config.THUMBNAIL_SIZE, Image.Resampling.LANCZOS)
                img.save(thumbnail_path, 'JPEG', quality=85)
                return True
        elif file_type == 'video':
            # Use ffmpeg to generate video thumbnail
            cmd = [
                'ffmpeg', '-i', file_path, '-ss', '00:00:01.000',
                '-vframes', '1', '-vf', f'scale={Config.THUMBNAIL_SIZE[0]}:{Config.THUMBNAIL_SIZE[1]}:force_original_aspect_ratio=decrease',
                '-y', thumbnail_path
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
    except Exception as e:
        print(f"Error generating thumbnail: {e}")
    return False

def refresh_jellyfin_library():
    """Trigger Jellyfin library refresh"""
    if not Config.JELLYFIN_API_KEY:
        return False
    
    try:
        headers = {'X-Emby-Token': Config.JELLYFIN_API_KEY}
        response = requests.post(
            f"{Config.JELLYFIN_URL}/Library/Refresh",
            headers=headers,
            timeout=10
        )
        return response.status_code == 204
    except Exception as e:
        print(f"Error refreshing Jellyfin library: {e}")
        return False

def validate_file_size(file_path, file_type):
    """Validate file size based on type"""
    try:
        file_size = os.path.getsize(file_path)
        max_size = Config.FILE_SIZE_LIMITS.get(file_type, Config.MAX_CONTENT_LENGTH)
        
        if file_size > max_size:
            return False, f"File too large. Maximum size for {file_type} files is {format_file_size(max_size)}"
        return True, None
    except Exception as e:
        return False, f"Error checking file size: {str(e)}"

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def count_nested_folders(base_path):
    """Count total number of folders including nested ones"""
    count = 0
    if not os.path.exists(base_path):
        return count
    
    try:
        for root, dirs, files in os.walk(base_path):
            count += len(dirs)
    except (OSError, PermissionError):
        pass
    
    return count

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('gallery'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = user_manager.verify_password(username, password)
        if user:
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('gallery'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match')
        elif user_manager.get_user_by_username(username):
            flash('Username already exists')
        elif len(password) < 6:
            flash('Password must be at least 6 characters long')
        else:
            user_manager.create_user(username, password)
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'files' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        files = request.files.getlist('files')
        custom_folder = request.form.get('custom_folder', '').strip()
        file_type_filter = request.form.get('file_type', '')
        
        # Sanitize custom folder path (can now be nested)
        if custom_folder:
            custom_folder = sanitize_folder_path(custom_folder)
            if not custom_folder:
                flash('Invalid folder path')
                return redirect(request.url)
        
        uploaded_files = []
        errors = []
        
        for file in files:
            if file.filename == '':
                continue
            
            is_allowed, file_type = allowed_file(file.filename)
            if not is_allowed:
                errors.append(f'File type not allowed: {file.filename}')
                continue
            
            # If file type filter is set, only allow that type
            if file_type_filter and file_type != file_type_filter:
                errors.append(f'File {file.filename} does not match selected type filter ({file_type_filter})')
                continue
            
            filename = secure_filename(file.filename)
            if not filename:
                continue
            
            # Get appropriate media directory
            media_dir = get_media_path(file_type)
            
            # Add custom folder if specified (now supports nested paths)
            if custom_folder:
                media_dir = os.path.join(media_dir, custom_folder)
            
            ensure_directory(media_dir)
            
            # Create thumbnails directory
            thumbnails_dir = os.path.join(app.static_folder, 'thumbnails')
            ensure_directory(thumbnails_dir)
            
            # Check if file already exists
            file_path = os.path.join(media_dir, filename)
            if os.path.exists(file_path):
                # Add timestamp to filename to avoid conflicts
                name, ext = os.path.splitext(filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{name}_{timestamp}{ext}"
                file_path = os.path.join(media_dir, filename)
            
            try:
                # For large files (especially videos), use chunked saving
                file_size = 0
                if hasattr(file, 'content_length') and file.content_length:
                    file_size = file.content_length
                
                # Check file size limit
                max_size = Config.FILE_SIZE_LIMITS.get(file_type, Config.MAX_CONTENT_LENGTH)
                if file_size > max_size:
                    errors.append(f'File {filename} is too large. Maximum size for {file_type} files is {format_file_size(max_size)}')
                    continue
                
                # Save file using chunked method for large files
                if file_size > 100 * 1024 * 1024:  # Use chunked saving for files > 100MB
                    success, error = chunked_file_save(file, file_path)
                    if not success:
                        errors.append(f'Failed to save {filename}: {error}')
                        continue
                else:
                    # Regular save for smaller files
                    file.save(file_path)
                
                # Validate saved file size
                is_valid, error_msg = validate_file_size(file_path, file_type)
                if not is_valid:
                    # Remove the invalid file
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    errors.append(f'{filename}: {error_msg}')
                    continue
                
                # Generate thumbnail
                thumbnail_filename = f"{hashlib.md5(file_path.encode()).hexdigest()}.jpg"
                thumbnail_path = os.path.join(thumbnails_dir, thumbnail_filename)
                
                if file_type in ['image', 'video']:
                    generate_thumbnail(file_path, file_type, thumbnail_path)
                
                uploaded_files.append({
                    'filename': filename,
                    'type': file_type,
                    'folder': custom_folder or 'Root',
                    'path': file_path,
                    'size': os.path.getsize(file_path),
                    'thumbnail': thumbnail_filename if os.path.exists(thumbnail_path) else None
                })
                
            except Exception as e:
                errors.append(f'Error uploading {filename}: {str(e)}')
                # Clean up partial file if it exists
                if os.path.exists(file_path):
                    os.remove(file_path)
        
        # Show results
        if uploaded_files:
            flash(f'Successfully uploaded {len(uploaded_files)} file(s)')
            # Show file sizes for large uploads
            for uploaded_file in uploaded_files:
                if uploaded_file['size'] > 100 * 1024 * 1024:  # > 100MB
                    flash(f"✓ {uploaded_file['filename']} ({format_file_size(uploaded_file['size'])})")
            
            # Refresh Jellyfin library
            if refresh_jellyfin_library():
                flash('Jellyfin library refresh triggered')
        
        if errors:
            for error in errors:
                flash(f'Error: {error}', 'error')
        
        return redirect(url_for('gallery'))
    
    # Get existing folders for each media type (now nested)
    folder_structure = {}
    for file_type in ['image', 'video', 'audio']:
        media_dir = get_media_path(file_type)
        folder_structure[file_type] = get_all_folder_paths(media_dir)
    
    return render_template('upload.html', 
                         folder_structure=folder_structure,
                         file_size_limits=Config.FILE_SIZE_LIMITS,
                         format_file_size=format_file_size)

@app.route('/gallery')
@login_required
def gallery():
    folder_filter = request.args.get('folder', '')
    file_type_filter = request.args.get('type', '')
    sort_by = request.args.get('sort', 'name')
    
    media_files = []
    folder_structure = {}
    
    # Scan all media directories
    for file_type in ['image', 'video', 'audio']:
        media_dir = get_media_path(file_type)
        folder_structure[file_type] = get_nested_folder_structure(media_dir)
        
        if file_type_filter and file_type != file_type_filter:
            continue
        
        if folder_filter:
            # Scan specific folder (now supports nested paths)
            files_in_folder = scan_media_files(media_dir, folder_filter)
            media_files.extend(files_in_folder)
        else:
            # Scan all files recursively
            files_in_dir = scan_media_files(media_dir)
            media_files.extend(files_in_dir)
    
    # Sort files
    if sort_by == 'size':
        media_files.sort(key=lambda x: x['size'], reverse=True)
    elif sort_by == 'date':
        media_files.sort(key=lambda x: x['modified'], reverse=True)
    elif sort_by == 'folder':
        media_files.sort(key=lambda x: (x['folder'], x['filename'].lower()))
    else:  # name
        media_files.sort(key=lambda x: x['filename'].lower())
    
    return render_template('gallery.html', 
                         files=media_files, 
                         folder_structure=folder_structure,
                         current_folder=folder_filter,
                         current_type=file_type_filter,
                         sort_by=sort_by)

@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    """Create a new folder in media directory"""
    folder_path = request.form.get('folder_path', '').strip()
    file_type = request.form.get('file_type', '')
    
    if not folder_path or not file_type:
        flash('Folder path and file type are required')
        return redirect(url_for('gallery'))
    
    # Sanitize folder path (now supports nested paths like "Anime/CowboyBebop")
    folder_path = sanitize_folder_path(folder_path)
    if not folder_path:
        flash('Invalid folder path')
        return redirect(url_for('gallery'))
    
    # Get media directory
    media_dir = get_media_path(file_type)
    full_folder_path = os.path.join(media_dir, folder_path)
    
    if os.path.exists(full_folder_path):
        flash(f'Folder "{folder_path}" already exists')
    else:
        try:
            ensure_directory(full_folder_path)
            flash(f'Folder "{folder_path}" created successfully')
        except Exception as e:
            flash(f'Error creating folder: {str(e)}')
    
    return redirect(url_for('gallery'))

@app.route('/browse_folders/<file_type>')
@login_required
def browse_folders(file_type):
    """API endpoint to browse folders for a specific media type"""
    if file_type not in ['image', 'video', 'audio']:
        return jsonify({'error': 'Invalid file type'}), 400
    
    media_dir = get_media_path(file_type)
    folder_structure = get_nested_folder_structure(media_dir)
    
    return jsonify({
        'folders': folder_structure,
        'flat_paths': get_all_folder_paths(media_dir)
    })

@app.route('/stream/<path:filename>')
@login_required
def stream_file(filename):
    """Stream media files with range support"""
    # Find file in media directories (including nested subfolders)
    file_path = None
    for file_type in ['image', 'video', 'audio']:
        media_dir = get_media_path(file_type)
        potential_path = os.path.join(media_dir, filename)
        
        # Normalize the path to handle different separators
        potential_path = os.path.normpath(potential_path)
        
        if os.path.exists(potential_path) and os.path.isfile(potential_path):
            file_path = potential_path
            break
    
    if not file_path:
        abort(404)
    
    # Handle range requests for streaming
    range_header = request.headers.get('Range', None)
    if not range_header:
        return send_file(file_path)
    
    size = os.path.getsize(file_path)
    byte_start = 0
    byte_end = size - 1
    
    if range_header:
        match = re.search(r'bytes=(\d+)-(\d*)', range_header)
        if match:
            byte_start = int(match.group(1))
            if match.group(2):
                byte_end = int(match.group(2))
    
    content_length = byte_end - byte_start + 1
    
    def generate():
        with open(file_path, 'rb') as f:
            f.seek(byte_start)
            remaining = content_length
            while remaining:
                chunk_size = min(4096, remaining)
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk
    
    response = Response(
        generate(),
        206,
        headers={
            'Content-Range': f'bytes {byte_start}-{byte_end}/{size}',
            'Accept-Ranges': 'bytes',
            'Content-Length': str(content_length),
            'Content-Type': mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        }
    )
    return response

@app.route('/thumbnail/<filename>')
def thumbnail(filename):
    """Serve thumbnails"""
    thumbnail_path = os.path.join(app.static_folder, 'thumbnails', filename)
    if os.path.exists(thumbnail_path):
        return send_file(thumbnail_path)
    abort(404)

@app.route('/admin')
@login_required
def admin():
    """Admin panel"""
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('gallery'))
    
    # Get system stats
    stats = {
        'total_users': len(user_manager.users),
        'total_files': 0,
        'total_size': 0,
        'folders': {'image': 0, 'video': 0, 'audio': 0}
    }
    
    for file_type in ['image', 'video', 'audio']:
        media_dir = get_media_path(file_type)
        if os.path.exists(media_dir):
            # Count folders (including nested ones)
            stats['folders'][file_type] = count_nested_folders(media_dir)
            
            # Count files
            files = scan_media_files(media_dir)
            stats['total_files'] += len(files)
            stats['total_size'] += sum(f['size'] for f in files)
    
    return render_template('admin.html', stats=stats)

@app.route('/delete/<path:filename>', methods=['POST'])
@login_required
def delete_file(filename):
    """Delete a file"""
    if not current_user.is_admin:
        abort(403)
    
    # Find and delete file (including in nested subfolders)
    file_path = None
    for file_type in ['image', 'video', 'audio']:
        media_dir = get_media_path(file_type)
        potential_path = os.path.join(media_dir, filename)
        potential_path = os.path.normpath(potential_path)
        
        if os.path.exists(potential_path) and os.path.isfile(potential_path):
            file_path = potential_path
            break
    
    if file_path:
        try:
            os.remove(file_path)
            
            # Remove thumbnail
            thumbnail_filename = f"{hashlib.md5(file_path.encode()).hexdigest()}.jpg"
            thumbnail_path = os.path.join(app.static_folder, 'thumbnails', thumbnail_filename)
            if os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)
            
            flash(f'File {os.path.basename(filename)} deleted successfully')
            refresh_jellyfin_library()
        except Exception as e:
            flash(f'Error deleting file: {str(e)}')
    else:
        flash(f'File {os.path.basename(filename)} not found')
    
    return redirect(url_for('gallery'))

# API Routes
@app.route('/api/files')
@login_required
def api_files():
    """REST API endpoint for listing files"""
    folder_filter = request.args.get('folder', '')
    type_filter = request.args.get('type', '')
    
    files = []
    
    for file_type in ['image', 'video', 'audio']:
        if type_filter and file_type != type_filter:
            continue
            
        media_dir = get_media_path(file_type)
        media_files = scan_media_files(media_dir, folder_filter)
        
        for file_data in media_files:
            files.append({
                'filename': file_data['filename'],
                'relative_path': file_data['relative_path'],
                'folder': file_data['folder'],
                'type': file_data['type'],
                'size': file_data['size'],
                'modified': file_data['modified'].isoformat(),
                'url': url_for('stream_file', filename=file_data['relative_path'])
            })
    
    return jsonify(files)

@app.route('/api/folders')
@login_required
def api_folders():
    """REST API endpoint for listing folders (now supports nested structure)"""
    file_type = request.args.get('type', '')
    flat = request.args.get('flat', 'false').lower() == 'true'
    
    if file_type and file_type in ['image', 'video', 'audio']:
        media_dir = get_media_path(file_type)
        if flat:
            folders = get_all_folder_paths(media_dir)
            return jsonify({file_type: folders})
        else:
            folders = get_nested_folder_structure(media_dir)
            return jsonify({file_type: folders})
    else:
        # Return all folders
        all_folders = {}
        for ftype in ['image', 'video', 'audio']:
            media_dir = get_media_path(ftype)
            if flat:
                all_folders[ftype] = get_all_folder_paths(media_dir)
            else:
                all_folders[ftype] = get_nested_folder_structure(media_dir)
        return jsonify(all_folders)

@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    """REST API endpoint for file upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    is_allowed, file_type = allowed_file(file.filename)
    if not is_allowed:
        return jsonify({'error': 'File type not allowed'}), 400
    
    # Get optional folder parameter (now supports nested paths)
    custom_folder = request.form.get('folder', '').strip()
    if custom_folder:
        custom_folder = sanitize_folder_path(custom_folder)
        if not custom_folder:
            return jsonify({'error': 'Invalid folder path'}), 400
    
    filename = secure_filename(file.filename)
    media_dir = get_media_path(file_type)
    
    # Add custom folder if specified (now supports nested paths)
    if custom_folder:
        media_dir = os.path.join(media_dir, custom_folder)
    
    ensure_directory(media_dir)
    
    file_path = os.path.join(media_dir, filename)
    
    # Handle file conflicts
    if os.path.exists(file_path):
        name, ext = os.path.splitext(filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{name}_{timestamp}{ext}"
        file_path = os.path.join(media_dir, filename)
    
    file.save(file_path)
    
    # Generate thumbnail
    thumbnails_dir = os.path.join(app.static_folder, 'thumbnails')
    ensure_directory(thumbnails_dir)
    thumbnail_filename = f"{hashlib.md5(file_path.encode()).hexdigest()}.jpg"
    thumbnail_path = os.path.join(thumbnails_dir, thumbnail_filename)
    
    if file_type in ['image', 'video']:
        generate_thumbnail(file_path, file_type, thumbnail_path)
    
    refresh_jellyfin_library()
    
    relative_path = os.path.join(custom_folder, filename) if custom_folder else filename
    
    return jsonify({
        'message': 'File uploaded successfully',
        'filename': filename,
        'relative_path': relative_path,
        'folder': custom_folder or 'Root',
        'type': file_type,
        'url': url_for('stream_file', filename=relative_path)
    })

@app.route('/api/delete/<path:filename>', methods=['DELETE'])
@login_required
def api_delete_file(filename):
    """REST API endpoint for file deletion"""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    # Find and delete file
    file_path = None
    for file_type in ['image', 'video', 'audio']:
        media_dir = get_media_path(file_type)
        potential_path = os.path.join(media_dir, filename)
        potential_path = os.path.normpath(potential_path)
        
        if os.path.exists(potential_path) and os.path.isfile(potential_path):
            file_path = potential_path
            break
    
    if not file_path:
        return jsonify({'error': 'File not found'}), 404
    
    try:
        os.remove(file_path)
        
        # Remove thumbnail
        thumbnail_filename = f"{hashlib.md5(file_path.encode()).hexdigest()}.jpg"
        thumbnail_path = os.path.join(app.static_folder, 'thumbnails', thumbnail_filename)
        if os.path.exists(thumbnail_path):
            os.remove(thumbnail_path)
        
        refresh_jellyfin_library()
        
        return jsonify({'message': f'File {filename} deleted successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to delete file: {str(e)}'}), 500

# Admin API Routes
@app.route('/api/admin/refresh-jellyfin', methods=['POST'])
@login_required
def api_refresh_jellyfin():
    """API endpoint to refresh Jellyfin library"""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    success = refresh_jellyfin_library()
    if success:
        return jsonify({'success': True, 'message': 'Jellyfin library refresh triggered'})
    else:
        return jsonify({'success': False, 'error': 'Failed to refresh Jellyfin library'})

@app.route('/api/admin/generate-thumbnails', methods=['POST'])
@login_required
def api_generate_thumbnails():
    """API endpoint to regenerate all thumbnails"""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    generated_count = 0
    thumbnails_dir = os.path.join(app.static_folder, 'thumbnails')
    ensure_directory(thumbnails_dir)
    
    for file_type in ['image', 'video']:
        media_dir = get_media_path(file_type)
        files = scan_media_files(media_dir)
        
        for file_data in files:
            if file_data['type'] in ['image', 'video']:
                thumbnail_filename = f"{hashlib.md5(file_data['full_path'].encode()).hexdigest()}.jpg"
                thumbnail_path = os.path.join(thumbnails_dir, thumbnail_filename)
                
                if generate_thumbnail(file_data['full_path'], file_data['type'], thumbnail_path):
                    generated_count += 1
    
    return jsonify({'generated': generated_count, 'message': f'Generated {generated_count} thumbnails'})

@app.route('/api/admin/cleanup-thumbnails', methods=['POST'])
@login_required
def api_cleanup_thumbnails():
    """API endpoint to cleanup orphaned thumbnails"""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    thumbnails_dir = os.path.join(app.static_folder, 'thumbnails')
    if not os.path.exists(thumbnails_dir):
        return jsonify({'removed': 0, 'message': 'No thumbnails directory found'})
    
    # Get all existing media file hashes
    valid_hashes = set()
    for file_type in ['image', 'video', 'audio']:
        media_dir = get_media_path(file_type)
        files = scan_media_files(media_dir)
        
        for file_data in files:
            file_hash = hashlib.md5(file_data['full_path'].encode()).hexdigest()
            valid_hashes.add(f"{file_hash}.jpg")
    
    # Remove orphaned thumbnails
    removed_count = 0
    for thumbnail_file in os.listdir(thumbnails_dir):
        if thumbnail_file not in valid_hashes:
            thumbnail_path = os.path.join(thumbnails_dir, thumbnail_file)
            try:
                os.remove(thumbnail_path)
                removed_count += 1
            except Exception as e:
                print(f"Failed to remove {thumbnail_file}: {e}")
    
    return jsonify({'removed': removed_count, 'message': f'Removed {removed_count} orphaned thumbnails'})

@app.route('/api/admin/stats', methods=['GET'])
@login_required
def api_admin_stats():
    """API endpoint for admin statistics"""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    stats = {
        'users': len(user_manager.users),
        'files': {'total': 0, 'by_type': {'image': 0, 'video': 0, 'audio': 0}},
        'storage': {'total_bytes': 0, 'by_type': {'image': 0, 'video': 0, 'audio': 0}},
        'folders': {'image': 0, 'video': 0, 'audio': 0},
        'thumbnails': 0
    }
    
    # Count files, storage, and folders
    for file_type in ['image', 'video', 'audio']:
        media_dir = get_media_path(file_type)
        files = scan_media_files(media_dir)
        
        stats['folders'][file_type] = count_nested_folders(media_dir)
        
        for file_data in files:
            stats['files']['total'] += 1
            stats['files']['by_type'][file_data['type']] += 1
            stats['storage']['total_bytes'] += file_data['size']
            stats['storage']['by_type'][file_data['type']] += file_data['size']
    
    # Count thumbnails
    thumbnails_dir = os.path.join(app.static_folder, 'thumbnails')
    if os.path.exists(thumbnails_dir):
        stats['thumbnails'] = len([f for f in os.listdir(thumbnails_dir) if f.endswith('.jpg')])
    
    return jsonify(stats)

@app.route('/api/create-folder', methods=['POST'])
@login_required
def api_create_folder():
    """API endpoint to create a new folder (now supports nested paths)"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    folder_path = data.get('folder_path', '').strip()
    file_type = data.get('file_type', '')
    
    if not folder_path or not file_type:
        return jsonify({'error': 'Folder path and file type are required'}), 400
    
    if file_type not in ['image', 'video', 'audio']:
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Sanitize folder path (now supports nested paths like "Anime/CowboyBebop")
    folder_path = sanitize_folder_path(folder_path)
    if not folder_path:
        return jsonify({'error': 'Invalid folder path'}), 400
    
    # Get media directory
    media_dir = get_media_path(file_type)
    full_folder_path = os.path.join(media_dir, folder_path)
    
    if os.path.exists(full_folder_path):
        return jsonify({'error': f'Folder "{folder_path}" already exists'}), 409
    
    try:
        ensure_directory(full_folder_path)
        return jsonify({
            'message': f'Folder "{folder_path}" created successfully', 
            'folder_path': folder_path
        })
    except Exception as e:
        return jsonify({'error': f'Error creating folder: {str(e)}'}), 500

@app.route('/api/delete-folder', methods=['DELETE'])
@login_required
def api_delete_folder():
    """API endpoint to delete a folder and all its contents (admin only)"""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    folder_path = data.get('folder_path', '').strip()
    file_type = data.get('file_type', '')
    
    if not folder_path or not file_type:
        return jsonify({'error': 'Folder path and file type are required'}), 400
    
    if file_type not in ['image', 'video', 'audio']:
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Sanitize folder path
    folder_path = sanitize_folder_path(folder_path)
    if not folder_path:
        return jsonify({'error': 'Invalid folder path'}), 400
    
    # Get media directory
    media_dir = get_media_path(file_type)
    full_folder_path = os.path.join(media_dir, folder_path)
    full_folder_path = os.path.normpath(full_folder_path)
    
    # Security check: ensure the path is within the media directory
    if not full_folder_path.startswith(os.path.normpath(media_dir)):
        return jsonify({'error': 'Invalid folder path'}), 400
    
    if not os.path.exists(full_folder_path):
        return jsonify({'error': f'Folder "{folder_path}" not found'}), 404
    
    if not os.path.isdir(full_folder_path):
        return jsonify({'error': f'"{folder_path}" is not a folder'}), 400
    
    try:
        # Count files that will be deleted
        deleted_files = 0
        deleted_thumbnails = 0
        
        # Walk through all files in the folder and subfolders
        for root, dirs, files in os.walk(full_folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                is_allowed, detected_type = allowed_file(file)
                if is_allowed:
                    deleted_files += 1
                    
                    # Remove corresponding thumbnail
                    thumbnail_filename = f"{hashlib.md5(file_path.encode()).hexdigest()}.jpg"
                    thumbnail_path = os.path.join(app.static_folder, 'thumbnails', thumbnail_filename)
                    if os.path.exists(thumbnail_path):
                        os.remove(thumbnail_path)
                        deleted_thumbnails += 1
        
        # Delete the entire folder
        import shutil
        shutil.rmtree(full_folder_path)
        
        # Refresh Jellyfin library
        refresh_jellyfin_library()
        
        return jsonify({
            'message': f'Folder "{folder_path}" deleted successfully',
            'deleted_files': deleted_files,
            'deleted_thumbnails': deleted_thumbnails
        })
        
    except Exception as e:
        return jsonify({'error': f'Error deleting folder: {str(e)}'}), 500

@app.route('/api/move-files', methods=['POST'])
@login_required
def api_move_files():
    """API endpoint to move files to a different folder"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    file_paths = data.get('file_paths', [])
    destination_folder = data.get('destination_folder', '').strip()
    destination_type = data.get('destination_type', '')
    
    if not file_paths:
        return jsonify({'error': 'No files specified for moving'}), 400
    
    if not destination_type or destination_type not in ['image', 'video', 'audio']:
        return jsonify({'error': 'Valid destination type required'}), 400
    
    # Sanitize destination folder path
    if destination_folder:
        destination_folder = sanitize_folder_path(destination_folder)
        if not destination_folder:
            return jsonify({'error': 'Invalid destination folder path'}), 400
    
    moved_files = []
    errors = []
    
    try:
        for file_path in file_paths:
            # Find the current file
            current_file_path = None
            current_file_type = None
            
            for file_type in ['image', 'video', 'audio']:
                media_dir = get_media_path(file_type)
                potential_path = os.path.join(media_dir, file_path)
                potential_path = os.path.normpath(potential_path)
                
                if os.path.exists(potential_path) and os.path.isfile(potential_path):
                    current_file_path = potential_path
                    current_file_type = file_type
                    break
            
            if not current_file_path:
                errors.append(f'File not found: {file_path}')
                continue
            
            # Check if file type matches destination type
            filename = os.path.basename(current_file_path)
            is_allowed, detected_type = allowed_file(filename)
            
            if not is_allowed:
                errors.append(f'Invalid file type: {filename}')
                continue
            
            if detected_type != destination_type:
                errors.append(f'File type mismatch: {filename} is {detected_type}, destination is {destination_type}')
                continue
            
            # Get destination directory
            dest_media_dir = get_media_path(destination_type)
            if destination_folder:
                dest_media_dir = os.path.join(dest_media_dir, destination_folder)
            
            ensure_directory(dest_media_dir)
            
            # Create destination path
            dest_file_path = os.path.join(dest_media_dir, filename)
            
            # Handle filename conflicts
            if os.path.exists(dest_file_path) and dest_file_path != current_file_path:
                name, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(dest_file_path):
                    new_filename = f"{name}_{counter}{ext}"
                    dest_file_path = os.path.join(dest_media_dir, new_filename)
                    counter += 1
                filename = os.path.basename(dest_file_path)
            
            # Skip if source and destination are the same
            if os.path.normpath(current_file_path) == os.path.normpath(dest_file_path):
                errors.append(f'File already in destination: {filename}')
                continue
            
            # Move the file
            import shutil
            shutil.move(current_file_path, dest_file_path)
            
            moved_files.append({
                'original_path': file_path,
                'new_path': os.path.join(destination_folder, filename) if destination_folder else filename,
                'filename': filename
            })
        
        # Refresh Jellyfin library
        if moved_files:
            refresh_jellyfin_library()
        
        return jsonify({
            'message': f'Successfully moved {len(moved_files)} file(s)',
            'moved_files': moved_files,
            'errors': errors
        })
        
    except Exception as e:
        return jsonify({'error': f'Error moving files: {str(e)}'}), 500

@app.route('/api/move-folder', methods=['POST'])
@login_required
def api_move_folder():
    """API endpoint to move/rename a folder"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON data required'}), 400
    
    source_folder = data.get('source_folder', '').strip()
    destination_folder = data.get('destination_folder', '').strip()
    file_type = data.get('file_type', '')
    
    if not source_folder or not destination_folder or not file_type:
        return jsonify({'error': 'Source folder, destination folder, and file type are required'}), 400
    
    if file_type not in ['image', 'video', 'audio']:
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Sanitize folder paths
    source_folder = sanitize_folder_path(source_folder)
    destination_folder = sanitize_folder_path(destination_folder)
    
    if not source_folder or not destination_folder:
        return jsonify({'error': 'Invalid folder paths'}), 400
    
    # Get media directory
    media_dir = get_media_path(file_type)
    source_path = os.path.join(media_dir, source_folder)
    dest_path = os.path.join(media_dir, destination_folder)
    
    source_path = os.path.normpath(source_path)
    dest_path = os.path.normpath(dest_path)
    
    # Security checks
    if not source_path.startswith(os.path.normpath(media_dir)) or not dest_path.startswith(os.path.normpath(media_dir)):
        return jsonify({'error': 'Invalid folder paths'}), 400
    
    if not os.path.exists(source_path):
        return jsonify({'error': f'Source folder "{source_folder}" not found'}), 404
    
    if not os.path.isdir(source_path):
        return jsonify({'error': f'"{source_folder}" is not a folder'}), 400
    
    if os.path.exists(dest_path):
        return jsonify({'error': f'Destination folder "{destination_folder}" already exists'}), 409
    
    try:
        # Ensure destination parent directory exists
        dest_parent = os.path.dirname(dest_path)
        ensure_directory(dest_parent)
        
        # Move the folder
        import shutil
        shutil.move(source_path, dest_path)
        
        # Refresh Jellyfin library
        refresh_jellyfin_library()
        
        return jsonify({
            'message': f'Folder moved from "{source_folder}" to "{destination_folder}" successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Error moving folder: {str(e)}'}), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error'), 500

# Template functions
@app.template_filter('filesize')
def filesize_filter(size):
    """Format file size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

if __name__ == '__main__':
    # Ensure required directories exist
    ensure_directory(Config.UPLOAD_FOLDER)
    ensure_directory(os.path.join(app.static_folder, 'thumbnails'))
    
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=True)