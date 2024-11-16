from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from datetime import timedelta
import os
import subprocess
import ipaddress
import re
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import logging
import json

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Update the paths based on your directories
# Flask app directory
BASE_DIR = '/www/wwwroot/targets.isvip.ir'

# Paths to the JSON target files in the Docker project
PING_TARGETS_FILE = '/root/docker-compose/monitoring/blackbox/ping/targets.json'
WEBSITE_TARGETS_FILE = '/root/docker-compose/monitoring/blackbox/website/targets.json'

# Path to the docker-compose directory
DOCKER_COMPOSE_DIR = '/root/docker-compose/monitoring'

# Tags options
TAGS_OPTIONS = [
    "DC-Sahand", "DC-Poonak", "DC-Shiraz", "DC-Tabriz", 
    "OVH", "Hetz", "Dedicated", "VPS OR VM", 
    "Win-OS", "Linux-OS", "Esxi-OS", 
    "EU", "IR", "Ping", "HTTP", 
    "Iran-Access", "CDN-UnderAttack"
]
# Set session timeout to 1 hour
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Configure logging
logging.basicConfig(filename='access.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')





# Load user credentials from users.json
with open('users.json', 'r') as f:
    user_credentials = json.load(f)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


#######create_user


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('create_user'))

        # Generate hashed password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Check if users.json exists and has valid content
        if not os.path.exists('users.json'):
            users_data = {}  # Start with an empty dictionary if file doesn't exist
        else:
            try:
                with open('users.json', 'r') as f:
                    users_data = json.load(f)
            except json.JSONDecodeError:
                flash('Error loading users data. JSON file might be corrupted.', 'danger')
                users_data = {}

        # Update users_data dictionary with new user
        users_data[username] = hashed_password

        # Save updated users data back to users.json
        try:
            with open('users.json', 'w') as f:
                json.dump(users_data, f, indent=2)
            flash('User created successfully.', 'success')
            logging.info(f'User {username} created.')
        except Exception as e:
            flash(f'Error saving user data: {e}', 'danger')
            return redirect(url_for('create_user'))

        return redirect(url_for('index'))

    # Render the template located in create_user/index.html
    return render_template('./create_user/index.html')




# @app.route('/create_user', methods=['GET', 'POST'])
# @login_required
# def create_user():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         if not username or not password:
#             flash('Username and password are required.', 'danger')
#             return redirect(url_for('create_user'))

#         # Generate hashed password
#         hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

#         # Load the users.json file and add the new user
#         with open('users.json', 'r') as f:
#             users_data = json.load(f)

#         users_data[username] = hashed_password

#         # Save the updated users data back to users.json
#         with open('users.json', 'w') as f:
#             json.dump(users_data, f, indent=2)

#         flash('User created successfully.', 'success')
#         logging.info(f'User {username} created.')
#         return redirect(url_for('index'))

#     # Render the template located in create_user/index.html
#     return render_template('./create_user/index.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Load users.json file to get user credentials
        try:
            with open('users.json', 'r') as f:
                user_credentials = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            flash('User data is not accessible or corrupted. Please contact the administrator.', 'danger')
            return render_template('login.html')

        # Check if the username exists and if the password is correct
        hashed_password = user_credentials.get(username)
        if hashed_password and check_password_hash(hashed_password, password):
            session['username'] = username
            session.permanent = True  # Mark session as permanent to apply the lifetime setting
            flash('Logged in successfully.', 'success')
            logging.info(f'User {username} logged in.')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')



########old login##########
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         hashed_password = user_credentials.get(username)
#         if hashed_password and check_password_hash(hashed_password, password):
#             session['username'] = username
#             session.permanent = True  # Mark session as permanent to apply the lifetime setting
#             flash('Logged in successfully.', 'success')
#             logging.info(f'User {username} logged in.')
#             return redirect(url_for('index'))
#         else:
#             flash('Invalid username or password.', 'danger')
#             return render_template('login.html')

#     return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    logging.info(f'User {username} logged out.')
    return redirect(url_for('login'))


@app.route('/', methods=['GET'])
@login_required
def index():
    return render_template('index.html', tags_options=TAGS_OPTIONS)

# Update the rest of the routes with @login_required as necessary
@app.route('/add', methods=['POST'])
@login_required
def add():
    ip = request.form.get('ip', '').strip()
    domain = request.form.get('domain', '').strip()
    customer_name = request.form.get('customer_name', '').strip()
    customer_number = request.form.get('customer_number', '').strip()
    tags = request.form.getlist('tags')

    # Trim whitespace from IP and domain
    ip = ip.strip()
    domain = domain.strip()

    # Validate mandatory fields
    if not customer_name or not customer_number:
        flash('Customer Name and Customer Number are required.', 'danger')
        return redirect(url_for('index'))

    if not tags:
        flash('Please select at least one tag.', 'danger')
        return redirect(url_for('index'))

    # Validate input
    if not ip and not domain:
        flash('Please provide at least an IP or a domain to add.', 'danger')
        return redirect(url_for('index'))

    errors = []  # Collect validation errors

    # Validation flags
    ip_valid = False
    domain_valid = False

    # Prepare descriptions
    if ip:
        # Validate IP address
        try:
            ipaddress.ip_address(ip)
            ip_valid = True
            ip_description = f"{customer_name}-{customer_number}-{ip}"
        except ValueError:
            errors.append(f'Invalid IP address: {ip}')

    if domain:
        # Validate domain name
        if not re.match(r'^https?://', domain):
            errors.append(f'Domain must start with http:// or https://: {domain}')
        else:
            domain_valid = True
            domain_without_protocol = re.sub(r'^https?://', '', domain)
            domain_description = f"{customer_name}-{customer_number}-{domain_without_protocol}"

    if errors:
        for error in errors:
            flash(error, 'danger')
        return redirect(url_for('index'))

    # Check for duplicates
    duplicates = []
    if ip_valid:
        if target_exists(PING_TARGETS_FILE, ip):
            duplicates.append(f'The IP "{ip}" already exists in ping targets.')
    if domain_valid:
        if target_exists(WEBSITE_TARGETS_FILE, domain):
            duplicates.append(f'The domain "{domain}" already exists in website targets.')

    if duplicates:
        for dup in duplicates:
            flash(dup, 'warning')
        flash('Duplicate targets were not added.', 'danger')
        return redirect(url_for('index'))

    # Proceed to add targets
    if ip_valid:
        add_target(PING_TARGETS_FILE, ip, ip_description, tags)
    if domain_valid:
        add_target(WEBSITE_TARGETS_FILE, domain, domain_description, tags)

    # Restart Prometheus container
    restart_prometheus()

    flash('Target(s) added successfully.', 'success')
    logging.info(f'User {session["username"]} added targets.')
    return redirect(url_for('index'))

@app.route('/delete', methods=['POST'])
@login_required
def delete():
    ip = request.form.get('ip', '').strip()
    domain = request.form.get('domain', '').strip()
    customer_number = request.form.get('customer_number', '').strip()

    # Trim whitespace from IP and domain
    ip = ip.strip()
    domain = domain.strip()

    # Ensure only one field is filled
    filled_fields = [bool(ip), bool(domain), bool(customer_number)]
    if sum(filled_fields) != 1:
        flash('Please provide exactly one field (IP, domain, or customer number) to delete.', 'danger')
        return redirect(url_for('index'))

    target_found = False

    if ip:
        target_found = delete_target(PING_TARGETS_FILE, target=ip)

    if domain:
        target_found = delete_target(WEBSITE_TARGETS_FILE, target=domain)

    if customer_number:
        found_in_ping = delete_target(PING_TARGETS_FILE, customer_number=customer_number)
        found_in_website = delete_target(WEBSITE_TARGETS_FILE, customer_number=customer_number)
        target_found = found_in_ping or found_in_website

    if not target_found:
        flash('Target not found. Nothing was deleted.', 'warning')
        return redirect(url_for('index'))

    # Restart Prometheus container
    restart_prometheus()

    flash('Target(s) deleted successfully.', 'success')
    logging.info(f'User {session["username"]} deleted targets.')
    return redirect(url_for('index'))



def add_target(file_path, target, description, tags):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    # Prepare the target item
    item = {
        "targets": [target],
        "labels": {
            "description": description
        }
    }

    # Add tags in the fixed order only if they are selected
    for idx, tag in enumerate(TAGS_OPTIONS, start=1):
        if tag in tags:
            item["labels"][f"tag{idx}"] = tag

    # Append the new target
    data.append(item)

    # Write back to the file
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

    return True  # Successfully added


# Helper function to order tags based on TAGS_OPTIONS
# def order_tags(selected_tags):
#     ordered_tags = []
#     for tag in TAGS_OPTIONS:
#         if tag in selected_tags:
#             ordered_tags.append(tag)
#     return ordered_tags


# def add_target(file_path, target, description, tags):
#     if os.path.exists(file_path):
#         with open(file_path, 'r') as f:
#             try:
#                 data = json.load(f)
#             except json.JSONDecodeError:
#                 data = []
#     else:
#         data = []

#     # Order the selected tags
#     ordered_tags = order_tags(tags)

#     # Prepare the target item
#     item = {
#         "targets": [target],
#         "labels": {
#             "description": description
#         }
#     }

#     # Add ordered tags as "tag1", "tag2", etc.
#     for idx, tag in enumerate(ordered_tags, start=1):
#         item["labels"][f"tag{idx}"] = tag

#     # Append the new target
#     data.append(item)

#     # Write back to the file
#     with open(file_path, 'w') as f:
#         json.dump(data, f, indent=2)

#     return True  # Successfully added



#####old add target###########
# def add_target(file_path, target, description, tags):
#     if os.path.exists(file_path):
#         with open(file_path, 'r') as f:
#             try:
#                 data = json.load(f)
#             except json.JSONDecodeError:
#                 data = []
#     else:
#         data = []

#     # Append the new target
#     item = {
#         "targets": [target],
#         "labels": {
#             "description": description,
#             "tags": ','.join(tags)
#         }
#     }

#     data.append(item)

#     # Write back to the file
#     with open(file_path, 'w') as f:
#         json.dump(data, f, indent=2)

#     return True  # Successfully added










def delete_target(file_path, target=None, customer_number=None):
    if not os.path.exists(file_path):
        return False  # File doesn't exist, nothing to delete

    with open(file_path, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []

    initial_length = len(data)

    # Filter out the targets to delete
    new_data = []
    for item in data:
        item_target = item['targets'][0]
        item_description = item['labels'].get('description', '')
        if target and item_target == target:
            continue  # Skip this item (delete)
        elif customer_number and f"-{customer_number}-" in item_description:
            continue  # Skip this item (delete)
        else:
            new_data.append(item)

    # Write the updated data back to the file
    with open(file_path, 'w') as f:
        json.dump(new_data, f, indent=2)

    return len(new_data) < initial_length  # Return True if something was deleted

def target_exists(file_path, target):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return False
    else:
        return False
    for item in data:
        if item['targets'][0] == target:
            return True
    return False

def restart_prometheus():
    try:
        subprocess.run(['docker', 'container', 'restart', 'prometheus'], cwd=DOCKER_COMPOSE_DIR, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error restarting Prometheus container: {e}")

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5200, debug=True)
