import csv
import json
import os
from io import StringIO, BytesIO
import csv
import ast
from flask import Flask, render_template, redirect, url_for, flash, request, session, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from jinja2 import Environment, FileSystemLoader
from werkzeug.utils import secure_filename
import forms
import api_calls

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

uploads_folder = 'uploads'
########################################################################################################################
# def parse_csv(csv_data):
#     csv_file = StringIO(csv_data)
#     csv_reader = list(csv.reader(csv_file))
#     headers = csv_reader[0]
#     data_rows = csv_reader[1:]
#     return headers, data_rows
#
# env = Environment(loader=FileSystemLoader('templates'))
# env.filters['parse_csv'] = parse_csv
#########################################################################################################################
password_reset_token = ""


@login_manager.user_loader
def load_user(user_id):
    response = api_calls.get_user_profile(access_token=user_id)
    if response.status_code == 200:
        user_data = response.json()
        user = User(user_id = user_id, role = user_data['role'],username = user_data['username'],email = user_data['email'])
        return user
    else:
        return None



class User(UserMixin):
    def __init__(self, user_id, role, username, email):
        self.id = user_id
        self.role = role
        self.username = username
        self.email = email




@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')



@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_pdf():
    form = forms.UploadForm()
    response = api_calls.get_user_profile(current_user.id)
    if (response.status_code == 200):
        result = response.json()
        username = result.get('username', '')
        email = result.get('email', '')
        role = result.get('role', '')

        if form.validate_on_submit():
            uploaded_files = request.files.getlist('files')
            print(len(uploaded_files))
            empty_uploads_folder()
            file_list = []
            print(len(uploaded_files))
            for file in uploaded_files:
                # Ensure the file has a secure filename
                filename = secure_filename(file.filename)
                # Save the file to a designated folder
                file_path = 'uploads/' + filename
                print(file_path)
                file.save(file_path)
                file_list.append(('pdf_files', (filename, open(file_path, 'rb'))))
                # files = [f for f in os.listdir(uploads_folder) if os.path.isfile(os.path.join(uploads_folder, f))]
                # file_list = [('pdf_files', (filename, open(os.path.join(uploads_folder, filename), 'rb'))) for filename in
                #              files]
                # file_list.append(('pdf_files', (filename, open(os.path.join(uploads_folder, filename), 'rb'))))
                # print(file_list)
            response = api_calls.dashboard(file_list, current_user.id)
            print(response.json())
            if response.status_code == 200:
                result = response.json()
                # Extract the CSV data from the response
                csv_data = result.get('csv_file', '')

                # Use StringIO to create a file-like object for the csv.reader
                csv_file = StringIO(csv_data)

                # Parse the CSV data into a list of lists
                csv_reader = list(csv.reader(csv_file))

                # The first row contains headers, and the rest are data rows
                headers = csv_reader[0]
                data_rows = csv_reader[1:]
                # Process the uploaded files or redirect to a new page
                xml_data = result.get('xml_file')
                return render_template('result.html', headers=headers, data_rows=data_rows, xml_data=xml_data, username=username, email=email, role=role)

    return render_template('upload_pdf.html', form=form, username=username, email=email, role=role)



def empty_uploads_folder():
    # Remove all files in the uploads folder
    for file in os.listdir(uploads_folder):
        file_path = os.path.join(uploads_folder, file)
        try:
            if os.path.isfile(file_path):
                with open(file_path, 'wb'):
                    pass  # This opens and immediately closes the file to release any locks
                os.unlink(file_path)
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")


@app.route("/login", methods=['GET', 'POST'])
def login():
    print('trying')
    if current_user.is_authenticated:
        return redirect(url_for('upload_pdf'))
    form = forms.LoginForm()
    print(form.validate_on_submit())
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        response = api_calls.user_login(email, password)

        if (response.status_code == 200):
            token = response.json().get('access_token')
            role = response.json().get('role')
            username = response.json().get('username')
            email = response.json().get('email')
            company_id = response.json().get('company_id')
            user = User(user_id=token,role=role,username=username,email=email)
            login_user(user)

            return redirect(url_for('upload_pdf'))
        else:
            flash('Login unsuccessful. Please check email and password.', category='error')

    return render_template('login.html', form=form)


@app.route("/register/<name>/<company_id>", methods=['GET', 'POST'])
def register(name, company_id):
    form = forms.RegisterForm()
    print("outside")
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        response = api_calls.user_register(username, email, password, company_id, company_name=name)
        print("inside")

        if (response.status_code == 200):
            flash('Registration Successful', category='info')
            return redirect(url_for('login'))
        else:
            flash('Registration unsuccessful. Please check username, email and password.', category='error')

    return render_template('register.html', form=form, company_id=company_id, company_name=name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))


@app.route('/result/<result>')
@login_required
def result():
    result = session.get('result', {})
    return render_template('result.html', result=result)


@app.route("/profile")
@login_required
def profile():
    response = api_calls.get_user_profile(current_user.id)
    if (response.status_code == 200):
        result = response.json()
        username = result.get('username', '')
        email = result.get('email', '')
        role = result.get('role', '')

        return render_template('profile.html', username=username, email=email, role=role)




@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    ITEMS_PER_PAGE = 5
    # Fetch user profile details
    respo = api_calls.get_user_profile(current_user.id)
    username, email, role = '', '', ''

    if respo.status_code == 200:
        admin_detail = respo.json()
        username = admin_detail.get('username', '')
        email = admin_detail.get('email', '')
        role = admin_detail.get('role', '')

    # Fetch all users

    response = api_calls.get_all_users(
        current_user.id,
    )

    if response.status_code == 200:
        result = response.json()
        users = result["users"]
    else:
        print("Failed response")

    return render_template('admin_panel.html', result=users, username=username, email=email, role=role)


@app.route("/admin/login", methods=['GET', 'POST'])
def admin_login():
    print('trying')
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    form = forms.LoginForm()
    print(form.validate_on_submit())
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        response = api_calls.admin_login(email, password)

        if (response.status_code == 200):
            token = response.json().get('access_token')
            role = response.json().get('role')
            username = response.json().get('username')
            email = response.json().get('email')
            company_id = response.json().get('company_id')
            user = User(user_id=token, role=role, username=username, email=email)
            login_user(user)

            return redirect(url_for('admin_dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', category='error')

    return render_template('admin_login.html', form=form)


@app.route("/admin/add-user", methods=['GET', 'POST'])
@login_required
def add_user():
    form = forms.AdminAddUserForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        role = form.role.data
        response = api_calls.add_user(username, email, password, role, current_user.id)
        print(response.status_code)
        if (response.status_code == 200):
            flash('Registration Successful', category='info')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Registration unsuccessful. Please check username, email and password.', category='error')

    return render_template('admin_add_user.html', form=form)


@app.route("/admin/delete-user/<user_id>", methods=['GET', 'POST'])
@login_required
def admin_delete_user(user_id):
    result = api_calls.admin_delete_user(access_token=current_user.id, user_id=user_id)
    if (result.status_code == 200):
        print(result)
        return redirect(url_for('admin_dashboard'))


@app.route("/admin/view-user-profile/<user_id>", methods=['GET', 'POST'])
@login_required
def admin_view_user_profile(user_id):
    user_role = current_user.role
    result = api_calls.admin_get_any_user(access_token=current_user.id, user_id=user_id)
    username = result["username"]
    email = result["email"]
    role = result["role"]

    resume_data = result["resume_data"]

    return render_template('admin_view_user_profile.html', resume_data=resume_data, email=email, role=role,
                           username=username, user_role=user_role)


@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('admin_login'))


@app.route("/profile/update_password/<role>", methods=['GET', 'POST'])
@login_required
def user_password_update(role):
    form = forms.UserPasswordUpdateForm()

    if form.validate_on_submit():

        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_new_password = form.confirm_new_password.data
        response = api_calls.update_user_password(current_password=current_password, new_password=new_password,
                                                  confirm_new_password=confirm_new_password,
                                                  access_token=current_user.id,username=current_user.username)
        print(response.status_code)
        if (response.status_code == 200):
            flash('Password Updated Successfully', category='info')
            if (role == 'user'):
                return redirect(url_for('profile'))
            else:
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Unsuccessful. Please check password.', category='error')
    return render_template('user_password_update.html', form=form, role=role)


@app.route("/forget-password", methods=['GET', 'POST'])
def forgot_password():
    form = forms.ForgetPasword()

    if form.validate_on_submit():
        email = form.email.data
        response = api_calls.forgot_password(email)
        print(response.status_code)
        if (response.status_code == 200):
            return render_template('mail_success.html')
    return render_template('forgot_password.html', form=form)


@app.route("/reset-password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    form = forms.ResetPasswordForm()
    if form.validate_on_submit():
        new_password = form.new_password.data
        response = api_calls.reset_password(token, new_password)
        print(response.status_code)
        if (response.status_code == 200):
            flash("Password updated successfully")
            return redirect(url_for('logout'))
    return render_template('reset_password.html', form=form, token=token)


@app.route("/user-history", methods=['GET', 'POST'])
@login_required
def user_history():
    response = api_calls.get_user_profile(access_token=current_user.id)
    if response.status_code == 200:
        result = response.json()
        username = result["username"]
        email = result["email"]
        role = result["role"]
        resume_data = result["resume_data"]
        # data_list = []
        # for index in range(len(result["resume_data"])):
        #     extracted_data = result["resume_data"][index]["extracted_data"]
        #     data_list.append(extracted_data)
    # template = env.get_template('admin_view_user_profile.html')
    # output = template.render(csv_files=csv_files, email=email, role = role, username=username)
    print(resume_data[0]["upload_datetime"])
    return render_template('admin_view_user_profile.html', email=email, role=role,
                           username=username, resume_data=resume_data)


@app.route("/admin/edit-user-profile/<user_id>", methods=['GET', 'POST'])
@login_required
def admin_edit_user_profile(user_id):
    form = forms.AdminEditUserForm()
    print(form.errors)
    result = api_calls.admin_get_any_user(access_token=current_user.id, user_id=user_id)
    username = result["username"]
    role = result["role"]
    status = result["status"]

    # Prefill the form fields with user information
    form.username.data = username
    form.role.data = role
    form.status.data = status

    if form.is_submitted():
        print("submitted")

    if form.validate_on_submit():
        # Update user information
        new_username = form.username.data
        new_role = form.role.data
        new_status = form.status.data

        response = api_calls.admin_edit_any_user(access_token=current_user.id, user_id=user_id,
                                                 username=new_username, role=new_role, status=new_status)
        print(response.status_code)
        if response.status_code == 200:
            return redirect(url_for('admin_dashboard'))

    return render_template('edit_form.html', status=status, role=role, username=username, form=form, user_id=user_id)


@app.route('/company-list', methods=['GET', 'POST'])
def company_list():
    response = api_calls.get_companies()
    companies = []

    if isinstance(response, list):  # Check if response is a list of dictionaries
        for company in response:
            id = company.get('id', '')
            name = company.get('name', '')
            phone_no = company.get('phone_no', '')
            email = company.get('email', '')
            address = company.get('address', '')
            description = company.get('description', '')
            companies.append({'id': id, 'name': name, 'phone_no': phone_no, 'email': email, 'address': address, 'description': description})
    else:
        # Handle the case when response is not a list of dictionaries
        app.logger.error('Error retrieving companies. Response: %s', response)

    return render_template('company_list.html', companies=companies)


@app.route('/company-details/<company_id>', methods=['GET', 'POST'])
def company_details(company_id):
    result = api_calls.get_company_details(company_id=company_id)

    name = result["name"]
    phone_no = result['phone_no']
    email = result['email']
    address = result['address']
    description = result['description']


    return render_template('company_details.html', company_id=company_id, name=name, phone_no=phone_no, email=email, address=address, description=description)


if __name__ == '__main__':
    app.run()