import csv
import json
import os
from io import StringIO, BytesIO
import csv
import ast

import stripe as stripe
from flask import Flask, render_template, redirect, url_for, flash, request, session, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from jinja2 import Environment, FileSystemLoader
from werkzeug.utils import secure_filename

import constants
import forms
import api_calls
from constants import ROOT_URL
import google.generativeai as genai

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

####################### GEMINI MODEL CONFIG #########################
genai.configure(api_key=constants.GEMINI_APIKEY)
model = genai.GenerativeModel('gemini-pro')

@login_manager.user_loader
def load_user(user_id):
    response = api_calls.get_user_profile(access_token=user_id)
    if response.status_code == 200:
        user_data = response.json()
        profile_picture = f"{ROOT_URL}/{user_data['profile_picture']}"

        # Create a User object using the retrieved data
        user = User(user_id=user_id, role=user_data['role'], username=user_data['username'], email=user_data['email'],
                    services=user_data['services'], company=user_data['company'], profile_picture=profile_picture)

        return user
    else:
        return None


class User(UserMixin):
    def __init__(self, user_id, role, username, email, services, company, profile_picture):
        self.id = user_id
        self.role = role
        self.username = username
        self.email = email
        self.services = services
        self.company = company
        self.profile_picture = profile_picture


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_pdf():
    form = forms.UploadForm()
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

        response = api_calls.dashboard(file_list, current_user.id)
        print(response.json())
        if response.status_code == 200:
            result = response.json()
            # Extract the CSV data from the response
            csv_data = result.get('extracted_data', [])

            # Use StringIO to create a file-like object for the csv.reader
            # csv_file = StringIO(csv_data)

            # Parse the CSV data into a list of lists
            # csv_reader = list(csv.reader(csv_file))
            #
            # The first row contains headers, and the rest are data rows
            # headers = csv_reader[0]
            # data_rows = csv_reader[1:]
            # Process the uploaded files or redirect to a new page
            xml_data = result.get('xml_file')
            return render_template('result.html', csv_data=csv_data, xml_data=xml_data)

    return render_template('upload_pdf.html', form=form)


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
    session.pop('_flashes', None)
    print('trying')
    if current_user.is_authenticated:
        if current_user.company is not None:
            return redirect(url_for('user_dashboard'))
        else:
            return redirect(url_for('company_register'))
    form = forms.LoginForm()
    print(form.validate_on_submit())
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        response = api_calls.user_login(email, password)

        if response is not None and response.status_code == 200:
            data = response.json()
            token = data.get('access_token')
            role = data.get('role')
            username = data.get('username')
            email = data.get('email')
            services = data.get('services', [])
            company = data.get('company', {})
            profile_picture = f"{ROOT_URL}/{data['profile_picture']}"

            user = User(user_id=token, role=role, username=username, email=email, services=services, company=company,
                        profile_picture=profile_picture)
            login_user(user)
            if current_user.company is not None:
                return redirect(url_for('user_dashboard'))
            else:
                return redirect(url_for('company_register'))
        elif response.status_code == 400:
            result = response.json()
            message = result["detail"]
            flash(message, category='error')
        else:
            # Handle the case where the response is None or the status code is not 200
            print("Error: Response is None or status code is not 200")
            flash('Login unsuccessful. Please check email and password.', category='error')

    return render_template('login.html', form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    session.pop('_flashes', None)
    form = forms.RegisterForm()
    print("outside")
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        response = api_calls.user_register(username, email, password)
        print("inside")
        if response.status_code == 200:
            response = api_calls.user_login(email, password)
            if response is not None and response.status_code == 200:
                data = response.json()
                token = data.get('access_token')
                role = data.get('role')
                username = data.get('username')
                email = data.get('email')
                services = data.get('services', [])
                company = data.get('company', {})
                profile_picture = f"{ROOT_URL}/{data['profile_picture']}"

                user = User(user_id=token, role=role, username=username, email=email, services=services,
                            company=company,
                            profile_picture=profile_picture)
                login_user(user)
            flash('Registration Successful', category='info')
            return redirect(url_for('user_view_plan'))
        elif response.status_code == 400:
            result = response.json()
            message = result["detail"]
            flash(message, category='error')

        else :
            flash('Registration unsuccessful. Please check username, email and password.', category='error')

    return render_template('register.html', form=form)


@app.route("/user-dashboard")
@login_required
def user_dashboard():
    response = api_calls.get_user_profile(access_token=current_user.id)
    if response.status_code == 200:
        result = response.json()
        resume_data = result["resume_data"]

    return render_template('dashboard.html', resume_data=resume_data)

@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    response = api_calls.get_all_users(current_user.id)

    if response.status_code == 200:
        users = response.json()

    return render_template('admin_dashboard.html', users=users)


@app.route("/setting")
@login_required
def setting():

    return render_template('setting.html')


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


@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = forms.UserEditUserForm()
    response = api_calls.get_user_profile(current_user.id)
    result = response.json()
    username = result["username"]
    email = result["email"]
    company = result.get('company', {})
    role = result.get('role', '')
    profile_picture = f"{ROOT_URL}/{result['profile_picture']}"
    current_plans = result.get('current_plans', [])
    print(current_plans)

    if form.validate_on_submit():
        # Update user information
        new_profile_picture = form.profile_picture.data
        if new_profile_picture:
            # Assuming the API call expects the file as part of the request
            new_username = form.username.data
            new_email = form.email.data
            # Ensure the file is included in the request
            response = api_calls.user_update_profile(access_token=current_user.id,
                                                     username=new_username, email=new_email, profile_picture=new_profile_picture)
            if response.status_code == 200:
                return redirect(url_for('profile'))
            else:
                # Handle error, e.g., flash a message
                pass
        else:
            # Handle case where no file is uploaded
            pass

    # Prefill the form fields with user information
    form.username.data = username
    form.email.data = email

    return render_template('profile.html', username=username, form=form, company=company, role=role, profile_picture=profile_picture, current_plans=current_plans)





@app.route("/list-of-users")
@login_required
def list_of_users():
    ITEMS_PER_PAGE = 5
    # Fetch user profile details
    # respo = api_calls.get_user_profile(current_user.id)
    # username, email, role = '', '', ''
    #
    # if respo.status_code == 200:
    #     admin_detail = respo.json()
    #     username = admin_detail.get('username', '')
    #     email = admin_detail.get('email', '')
    #     role = admin_detail.get('role', '')

    # Fetch all users

    response = api_calls.get_all_users(
        current_user.id,
    )

    if response.status_code == 200:
        users = response.json()

    else:
        print("Failed response")


    return render_template('list_of_users.html', result=users)




@app.route("/admin/login", methods=['GET', 'POST'])
def admin_login():
    session.pop('_flashes', None)
    print('trying')
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))

    form = forms.LoginForm()
    print(form.validate_on_submit())

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        response = api_calls.admin_login(email, password)



        # if response.status_code == 200:
        #     data = response.json()
        #     token = data.get('access_token')
        #     role = data.get('role')
        #     username = data.get('username')
        #     email = data.get('email')
        #     services = data.get('services')
        #     company = data.get('company')


        if (response.status_code == 200):
            token = response.json().get('access_token')
            role = response.json().get('role')
            username = response.json().get('username')
            email = response.json().get('email')
            profile_picture = f"{ROOT_URL}/{response.json()['profile_picture']}"
            user = User(user_id=token, role=role, username=username, email=email, services=[], company={},profile_picture=profile_picture)
            login_user(user)


            # user = User(user_id=token, role=role, username=username, email=email, services=services, company=company)
            # login_user(user)

            return redirect(url_for('admin_dashboard'))
        elif response.status_code == 400:
            result = response.json()
            message = result["detail"]
            flash(message, category='error')
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


@app.route("/admin/trash-user/<user_id>", methods=['GET', 'POST'])
@login_required
def admin_trash_user(user_id):
    result = api_calls.admin_trash_user(access_token=current_user.id, user_id=user_id)
    if (result.status_code == 200):
        print(result)
        return redirect(url_for('list_of_users'))

@app.route("/admin/delete-user/<user_id>", methods=['GET', 'POST'])
@login_required
def admin_delete_user_permanently(user_id):
    result = api_calls.admin_delete_user_permanently(access_token=current_user.id, user_id=user_id)
    if (result.status_code == 200):
        print(result)
        return redirect(url_for('list_of_users'))

@app.route("/admin/restore-user/<user_id>", methods=['GET', 'POST'])
@login_required
def admin_restore_user(user_id):
    result = api_calls.admin_restore_user(access_token=current_user.id, user_id=user_id)
    if (result.status_code == 200):
        print(result)
        return redirect(url_for('list_of_users'))


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


@app.route("/profile/update_password/", methods=['GET', 'POST'])
@login_required
def user_password_update():
    form = forms.UserPasswordUpdateForm()

    if form.validate_on_submit():

        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_new_password = form.confirm_new_password.data
        response = api_calls.update_user_password(current_password=current_password, new_password=new_password,
                                                  confirm_new_password=confirm_new_password,
                                                  access_token=current_user.id)
        print(response.status_code)
        if response.status_code == 200:
            flash('Password Updated Successfully', category='info')
            if current_user.role == 'user':
                return redirect(url_for('profile'))
            else:
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Unsuccessful. Please check password.', category='error')
    return render_template('user_password_update.html', form=form)


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
    # print(resume_data[0]["upload_datetime"])
    return render_template('admin_view_user_profile.html', email=email, role=role,
                           username=username, resume_data=resume_data)


@app.route("/admin/edit-user-profile/<user_id>", methods=['GET', 'POST'])
@login_required
def admin_edit_user_profile(user_id):
    form = forms.AdminEditUserForm()
    result = api_calls.admin_get_any_user(access_token=current_user.id, user_id=user_id)
    username = result["username"]
    role = result["role"]
    status = result["status"]
    service_response = api_calls.services()

    all_service = None
    if service_response.status_code == 200:
        all_service = service_response.json()

    user_services = None
    user_service_response = api_calls.user_specific_services(user_id=user_id)
    if user_service_response.status_code == 200:
        user_services = user_service_response.json()
        print(user_services)

    if form.validate_on_submit():
        new_username = form.username.data
        new_role = form.role.data
        new_status = form.status.data

        response = api_calls.admin_edit_any_user(access_token=current_user.id, user_id=user_id,
                                                 username=new_username, role=new_role, status=new_status)

        if response.status_code == 200:
            return redirect(url_for('admin_edit_user_profile', user_id=user_id))

    form.username.data = username
    form.role.data = role
    form.status.data = status

    service_form = forms.ServiceForm()
    if service_form.validate_on_submit():
        selected_services = [int(service) for service in request.form.getlist('services')]
        response_service = api_calls.admin_assign_service(user_id=user_id, service_ids=selected_services)
        if response_service.status_code == 200:
            print("Selected Services:", selected_services)
            return redirect(url_for('admin_edit_user_profile', user_id=user_id))

    return render_template('edit_form.html', status=status, role=role, username=username, form=form,
                           user_id=user_id, all_service=all_service, service_form=service_form,
                           user_services=user_services)



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
            companies.append({'id': id, 'name': name, 'phone_no': phone_no, 'email': email, 'address': address,
                              'description': description})
    else:
        # Handle the case when response is not a list of dictionaries
        app.logger.error('Error retrieving companies. Response: %s', response)

    return render_template('company_list.html', companies=companies)


@app.route('/companies/<company_id>', methods=['GET', 'POST'])
def company_details(company_id):
    result = api_calls.get_company_details(company_id=company_id)

    name = result["name"]
    location = result["location"]

    return render_template('company_details.html', name=name, location= location)


################################################################ SERVICES ############################################################################################
@app.route('/services', methods=['GET', 'POST'])
def services():
    response = api_calls.services()
    if response.status_code == 200:
        result = response.json()
        return render_template('services.html', result=result)

@app.route("/admin/add-service", methods=['GET', 'POST'])
@login_required
def add_service():
    form = forms.AdminAddServiceForm()
    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        response = api_calls.add_service(name, description)
        print(response.status_code)
        if (response.status_code == 200):
            flash('Service added Successful', category='info')
            return redirect(url_for('services'))
        else:
            flash('Some problem occured', category='error')

    return render_template('admin_add_service.html', form=form)


@app.route("/admin/delete-service/<service_id>", methods=['GET', 'POST'])
@login_required
def admin_delete_service(service_id):
    result = api_calls.admin_delete_service(service_id=service_id)
    if (result.status_code == 200):
        print(result)
        return redirect(url_for('services'))


@app.route("/admin/edit-service/<service_id>", methods=['GET', 'POST'])
@login_required
def admin_edit_service(service_id):
    form = forms.AdminEditServiceForm()
    result = api_calls.admin_get_any_service(service_id=service_id)
    name = result["service_name"]
    description = result["service_description"]

    if form.validate_on_submit():
        # Update user information
        name = form.name.data
        description = form.description.data

        response = api_calls.admin_edit_any_service(service_id=service_id,
                                                 service_name=name, service_description=description)
        print(response.status_code)
        if response.status_code == 200:
            return redirect(url_for('services'))

    # Prefill the form fields with user information
    form.name.data = name
    form.description.data = description

    return render_template('admin_edit_service.html', description=description, name=name, form=form, service_id=service_id)

########################################################################## COMPANIES ###############################################################3

@app.route("/admin/list-of-companies", methods=['GET', 'POST'])
@login_required
def list_of_companies():
    response = api_calls.admin_get_all_companies()
    if (response.status_code == 200):
        result = response.json()
        print(result)
    return render_template('list_of_companies.html', result=result)


@app.route("/admin/delete-company/<company_id>", methods=['GET', 'POST'])
@login_required
def admin_delete_company(company_id):
    result = api_calls.admin_delete_company(company_id=company_id)
    if (result.status_code == 200):
        return redirect(url_for('list_of_companies'))


@app.route("/admin/edit-company/<company_id>", methods=['GET', 'POST'])
@login_required
def admin_edit_company(company_id):
    form = forms.AdminEditCompanyForm()
    result = api_calls.admin_get_any_company(company_id)
    name = result["name"]
    location = result["location"]

    if form.validate_on_submit():
        # Update user information
        name = form.name.data
        location = form.location.data
        print(location)

        response = api_calls.admin_edit_any_company(company_id=company_id,
                                                 name=name, location=location)
        print(response.status_code)
        if response.status_code == 200:
            return redirect(url_for('list_of_companies'))

    # Prefill the form fields with user information
    form.name.data = name
    form.location.data = location

    return render_template('admin_edit_company.html', location=location, name=name, form=form, company_id=company_id)


@app.route("/company-register", methods=['GET', 'POST'])
def company_register():
    form = forms.CompanyRegisterForm()
    print("outside")
    if form.validate_on_submit():
        name = form.name.data
        location = form.location.data
        response = api_calls.company_register(name, location, access_token=current_user.id)
        print("inside")

        if (response.status_code == 200):
            flash('Registration Successful', category='info')
            if (current_user.role == 'user'):
                return redirect(url_for('user_dashboard'))
            else:
                return redirect(url_for('list_of_companies'))
        else:
            flash('Registration unsuccessful.', category='error')

    return render_template('company_register.html', form=form)



######################################## resume history ##########################################################################
@app.route("/resume-history", methods=['GET', 'POST'])
@login_required
def resume_history():
    response = api_calls.admin_get_resume_history()
    if response.status_code == 200:
        result = response.json()
        return render_template('resume_history.html', result=result)

####################################### trash ##########################################################################
@app.route("/trash")
@login_required
def trash():

    response = api_calls.get_trash_users(
        current_user.id,
    )

    if response.status_code == 200:
        users = response.json()

    else:
        print("Failed response")

    return render_template('trash.html', result=users )

####################################### EMAIL SETUP ##########################################################################
@app.route("/admin/email-setup", methods=['GET', 'POST'])
@login_required
def admin_email_setup():
    result = api_calls.admin_get_email_setup(access_token=current_user.id)
    form = forms.EmailFunctionalityForm()

    if result.status_code == 200:
        email_details = result.json()
        smtp_server = email_details.get("smtp_server")
        smtp_port = email_details.get("smtp_port")
        smtp_username = email_details.get("smtp_username")
        smtp_password = email_details.get("smtp_password")
        sender_email = email_details.get("sender_email")
        if form.validate_on_submit():

            new_smtp_server = form.smtp_server.data
            new_smtp_port = form.smtp_port.data
            new_smtp_username = form.smtp_username.data
            new_smtp_password = form.smtp_password.data
            new_sender_email = form.sender_email.data
            # Ensure the file is included in the request
            response = api_calls.admin_update_email_setup(access_token=current_user.id,
                                                     smtp_server=new_smtp_server, smtp_port=new_smtp_port, smtp_username=new_smtp_username,
                                                     smtp_password=new_smtp_password, sender_email=new_sender_email)
            if response.status_code == 200:
                return redirect(url_for('admin_email_setup'))


        form.smtp_server.data = smtp_server
        form.smtp_port.data = smtp_port
        form.smtp_username.data = smtp_username
        form.smtp_password.data = smtp_password
        form.sender_email.data = sender_email

    return render_template('email_form.html', form=form)


################################################################ PLANS ########################################################################
@app.route("/admin/settings/plans", methods=['GET', 'POST'])
@login_required
def list_of_plans():
    result = api_calls.get_all_plans()
    return render_template('admin_plan_page.html', result=result)


@app.route('/admin/settings/add-plan', methods=['GET', 'POST'])
def add_plan():
    form = forms.AddPlan()
    print("outside validate on submit")
    if form.validate_on_submit():
        name = form.name.data
        duration = form.duration.data
        fees = 0 if form.is_free.data else form.fees.data
        num_resume_parsing = 'unlimited' if form.unlimited_resume_parsing.data else form.num_resume_parsing.data
        plan_details = form.plan_details.data
        print("sending request to add plan")
        result = api_calls.create_plan(plan_name=name, time_period=duration, fees=fees, num_resume_parse=num_resume_parsing, plan_details=plan_details)
        if result:
            return redirect(url_for('list_of_plans'))
    else:
        print(form.errors)

    return render_template('add_plan.html', form=form)


@app.route("/admin/settings/update-plan/<plan_id>", methods=['GET', 'POST'])
@login_required
def update_plan(plan_id):
    form = forms.AddPlan()
    result = api_calls.get_plan_by_id(plan_id)
    name = result["plan_type_name"]
    duration = result["time_period"]
    fees = result["fees"]
    num_resume_parse = result["num_resume_parse"]
    plan_details = result["plan_details"]

    if form.validate_on_submit():
        # Update user information
        name = form.name.data
        duration = form.duration.data
        fees = 0 if form.is_free.data else form.fees.data
        num_resume_parsing = 'unlimited' if form.unlimited_resume_parsing.data else form.num_resume_parsing.data
        plan_details = form.plan_details.data
        result = api_calls.update_plan(plan_id=plan_id, plan_name=name, time_period=duration, fees=fees, num_resume_parse=num_resume_parsing, plan_details=plan_details)
        if result:
            return redirect(url_for('list_of_plans'))
    else:
        print(form.errors)

    # Prefill the form fields with user information
    form.name.data = name
    form.duration.data = duration
    form.plan_details.data = plan_details
    if fees == 0:
        form.is_free.data = True
    else:
        form.fees.data = fees
    if num_resume_parse == 'unlimited':
        form.unlimited_resume_parsing.data = True
    else:
        form.num_resume_parsing.data = num_resume_parse

    return render_template('update_plan.html', form=form, plan_id=plan_id)


@app.route("/admin/settings/plans/delete-plan/<plan_id>", methods=['GET', 'POST'])
@login_required
def delete_plan(plan_id):
    result = api_calls.delete_plan(plan_id=plan_id)
    if result:
        return redirect(url_for('list_of_plans'))


@app.route("/pricing", methods=['GET', 'POST'])
def user_view_plan():
    result = api_calls.get_all_plans()
    return render_template('pricing.html', result=result)


@app.route('/admin/posts')
@login_required
def all_post():
    result = api_calls.get_all_posts()
    if result is None:
        result = []  # Set result to an empty list
    print(result)

    return render_template('all_posts.html', result=result)


@app.route('/user/all-posts')
@login_required
def user_all_post():
    result = api_calls.get_user_all_posts(access_token=current_user.id)
    if result is None:
        result = []  # Set result to an empty list



    return render_template('user_all_post.html', result=result)


@app.route('/<username>/posts')
def user_post_list(username):

    result = api_calls.get_user_post_by_username(username=username)

    response = api_calls.get_all_categories()
    if result is None:
        result = []  # Set result to an empty list

    if response is None:
        response = []
    return render_template('user_post_list.html', result=result, response=response)

@app.route("/admin/delete-posts/<post_id>", methods=['GET', 'POST'])
@login_required
def admin_delete_post(post_id):
    result = api_calls.admin_delete_post(post_id=post_id, access_token=current_user.id)

    # Print the status code for debugging purposes
    print(result.status_code)

    if result.status_code == 200:
        flash('Post deleted successfully', category='info')
        return redirect(url_for('all_post'))



@app.route("/user/delete-posts/<post_id>", methods=['GET', 'POST'])
@login_required
def user_delete_post(post_id):
    result = api_calls.admin_delete_post(post_id=post_id, access_token=current_user.id)
    print(result.status_code)
    if result.status_code == 200:
        return redirect(url_for('user_all_post'))


@app.route('/posts/add-post', methods=['GET', 'POST'])
def add_post():
    form = forms.AddPost()

    # Fetch categories and format them for the form choices
    try:
        categories = api_calls.get_user_all_categories(access_token=current_user.id)
        category_choices = [('', 'Select a category')] + [(category['id'], category['category']) for category in categories]
        if not category_choices:
            category_choices = [('', 'Select Category')]
    except Exception as e:
        print(f"Error fetching categories: {e}")
        category_choices = [('', 'Select Category')]

    form.category.choices = category_choices

    if form.category.data:
        # Fetch subcategories based on the selected category
        try:
            subcategories = api_calls.get_subcategories_by_category(form.category.data)
            subcategory_choices = [(subcategory['id'], subcategory['subcategory']) for subcategory in subcategories]
            if not subcategory_choices:
                subcategory_choices = [('', 'Select Subcategory')]
        except Exception as e:
            print(f"Error fetching subcategories: {e}")
            subcategory_choices = [('', 'Select Subcategory')]
        form.subcategory.choices = subcategory_choices

    # Fetch tags and format them for the form choices
    try:
        tags = api_calls.get_user_all_tags(access_token=current_user.id)
        tag_choices = [(tag['id'], tag['tag']) for tag in tags]
        if not tag_choices:
            tag_choices = [('', 'Select Tag')]
    except Exception as e:
        print(f"Error fetching tags: {e}")
        tag_choices = [('', 'Select Tag')]

    form.tags.choices = tag_choices

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        category = form.category.data
        subcategory = form.subcategory.data
        tag = form.tags.data

        print(content)

        try:
            result = api_calls.create_post(
                title=title,
                content=content,
                category_id=category,
                subcategory_id=subcategory,
                tag_id=tag,
                access_token=current_user.id
            )

            if result:
                flash("Post created successfully", "success")
                if current_user.role == 'user':
                    return redirect(url_for('view_post'))
                else:
                    return redirect(url_for('all_post'))
            else:
                flash("Failed to create post", "danger")
        except Exception as e:
            flash(f"Error creating post: {e}", "danger")
    else:
        if request.method == 'POST':
            flash("Form validation failed", "danger")
            print(form.errors)

    if current_user.role == 'user':
        # for service in current_user.services:
        is_service_allowed = api_calls.is_service_access_allowed(current_user.id)
        if is_service_allowed :
            return render_template('add_post.html', form=form, categories=category_choices)
        return redirect(url_for('user_view_plan'))
    else:
        return render_template('add_post.html', form=form, categories=category_choices)



@app.route("/user/add-category", methods=['GET', 'POST'])
@login_required
def add_category():
    form = forms.AddCategory()
    if form.validate_on_submit():
        category = form.category.data
        response = api_calls.add_category(category, access_token=current_user.id)
        print(response.status_code)
        if (response.status_code == 200):
            flash('Category added Successful', category='info')
            return redirect(url_for('user_all_category'))
        else:
            flash('Some problem occured', category='error')

    return render_template('user_add_category.html', form=form)


@app.route("/user/update-category/<category_id>", methods=['GET', 'POST'])
@login_required
def update_category(category_id):
    form = forms.AddCategory()
    if form.validate_on_submit():
        category = form.category.data
        response = api_calls.update_category(category_id, category, access_token=current_user.id)
        print(response.status_code)
        if (response.status_code == 200):
            flash('Category updated Successful', category='info')
            return redirect(url_for('user_all_category'))
        else:
            flash('Some problem occured', category='error')

    return render_template('update_user_category.html', form=form, category_id=category_id)

@app.route('/user/all-categories')
@login_required
def user_all_category():
    result = api_calls.get_user_all_categories(access_token=current_user.id)
    if result is None:
        result = []  # Set result to an empty list
    print(result)

    return render_template('view_user_category.html', result=result)




@app.route('/user/all-subcategories/<category_id>')
@login_required
def user_all_subcategory(category_id):
    result = api_calls.get_subcategories_by_category(category_id=category_id)
    if result is None:
        result = []  # Set result to an empty list
    print(result)

    return render_template('view_user_subcategory.html', result=result)

@app.route("/user/add-tag", methods=['GET', 'POST'])
@login_required
def add_tag():
    form = forms.AddTag()
    if form.validate_on_submit():
        tag = form.tag.data
        response = api_calls.add_tag(tag, access_token=current_user.id)
        print(response.status_code)
        if (response.status_code == 200):
            flash('Tag added Successful')
            return redirect(url_for('user_all_tag'))
        else:
            flash('Some problem occured')

    return render_template('user_add_tags.html', form=form)


@app.route("/user/edit-tag/<int:tag_id>", methods=['GET', 'POST'])
@login_required
def edit_tag(tag_id):
    form = forms.EditTag()
    if form.validate_on_submit():
        new_tag = form.tag.data
        response = api_calls.edit_tag(tag_id, new_tag, access_token=current_user.id)
        print(response.status_code)
        if response.status_code == 200:
            flash('Tag edited successfully')
            return redirect(url_for('user_all_tag'))
        else:
            flash('Some problem occurred while editing the tag')


    return render_template('user_edit_tag.html', form=form, tag_id=tag_id)


@app.route("/user/delete-tag/<int:tag_id>", methods=['GET', 'POST'])
@login_required
def delete_tag(tag_id):
    response = api_calls.delete_tag(tag_id, access_token=current_user.id)
    print(response.status_code)
    if response.status_code == 200:
        flash('Tag deleted successfully')
    else:
        flash('Some problem occurred while deleting the tag')
    return redirect(url_for('user_all_tag'))


@app.route('/user/all-tags')
@login_required
def user_all_tag():
    result = api_calls.get_user_all_tags(access_token=current_user.id)
    if result is None:
        result = []  # Set result to an empty list
    print(result)

    return render_template('view_user_tags.html', result=result)


@app.route("/users/delete-category/<category_id>", methods=['GET', 'POST'])
@login_required
def user_delete_category(category_id):
    result = api_calls.user_delete_category(category_id=category_id, access_token=current_user.id)
    print(result.status_code)
    if result.status_code == 200:
        return redirect(url_for('user_all_category'))

@app.route('/subcategories/<int:category_id>')
def get_subcategories(category_id):
    # Fetch subcategories based on the category_id
    subcategories = api_calls.get_subcategories_by_category(category_id)
    return jsonify({'subcategories': subcategories})


@app.route("/user/add-subcategory", methods=['GET', 'POST'])
@login_required
def add_subcategory():
    form = forms.AddSubcategory()
    categories = api_calls.get_user_all_categories(access_token=current_user.id)
    category_choices = [(category['id'], category['category']) for category in categories]
    form.category.choices = category_choices
    if form.validate_on_submit():
        subcategory = form.subcategory.data
        category_id = form.category.data
        response = api_calls.add_subcategory(subcategory, category_id, access_token=current_user.id)
        print(response.status_code)
        if (response.status_code == 200):
            flash('Subcategory added Successful', category='info')
            return redirect(url_for('user_all_category'))
        else:
            flash('Some problem occured', category='error')

    return render_template('user_add_subcategory.html', form=form, categories=category_choices)


@app.route("/user/update-subcategory/<subcategory_id>", methods=['GET', 'POST'])
@login_required
def update_subcategory(subcategory_id):
    form = forms.AddSubcategory()  # Assuming you have a form for subcategory
    categories = api_calls.get_user_all_categories(access_token=current_user.id)
    category_choices = [(category['id'], category['category']) for category in categories]
    form.category.choices = category_choices
    if form.validate_on_submit():
        subcategory = form.subcategory.data
        category_id = form.category.data
        response = api_calls.update_subcategory(subcategory_id, subcategory, category_id, access_token=current_user.id)
        print(response.status_code)
        if (response.status_code == 200):
            flash('Subcategory added Successful', category='info')
            return redirect(url_for('user_all_category'))
        else:
            flash('Some problem occured', category='error')

    return render_template('update_user_subcategory.html', form=form, subcategory_id=subcategory_id, categories=category_choices)

@app.route("/users/delete-subcategory/<subcategory_id>", methods=['GET', 'POST'])
@login_required
def user_delete_subcategory(subcategory_id):
    result = api_calls.user_delete_subcategory(subcategory_id=subcategory_id, access_token=current_user.id)
    print(result.status_code)
    if result.status_code == 200:
        return redirect(url_for('user_all_category'))


@app.route('/posts/edit-post/<post_id>', methods=['GET', 'POST'])
def admin_edit_post(post_id):
    form = forms.AdminUpdatePost()

    # Fetch categories and format them for the form choices
    try:
        categories = api_calls.get_user_all_categories(access_token=current_user.id)
        category_choices = [(category['id'], category['category']) for category in categories]
        if not category_choices:
            category_choices = [('', 'Select Category')]
    except Exception as e:
        print(f"Error fetching categories: {e}")
        category_choices = [('', 'Select Category')]
    form.category.choices = category_choices

    # If a category is selected, fetch and set subcategories
    if form.category.data:
        try:
            subcategories = api_calls.get_subcategories_by_category(form.category.data)
            subcategory_choices = [(subcategory['id'], subcategory['subcategory']) for subcategory in subcategories]
            if not subcategory_choices:
                subcategory_choices = [('', 'Select Subcategory')]
        except Exception as e:
            print(f"Error fetching subcategories: {e}")
            subcategory_choices = [('', 'Select Subcategory')]
        form.subcategory.choices = subcategory_choices

    # Fetch tags and format them for the form choices
    try:
        tags = api_calls.get_user_all_tags(access_token=current_user.id)
        tag_choices = [(tag['id'], tag['tag']) for tag in tags]
        if not tag_choices:
            tag_choices = [('', 'Select Tag')]
    except Exception as e:
        print(f"Error fetching tags: {e}")
        tag_choices = [('', 'Select Tag')]
    form.tags.choices = tag_choices

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        category = form.category.data
        subcategory = form.subcategory.data
        tag = form.tags.data

        try:
            result = api_calls.admin_update_post(
                post_id=post_id,
                title=title,
                content=content,
                category_id=category,
                subcategory_id=subcategory,
                tag_id=tag,
                access_token=current_user.id
            )

            if result:
                print("Post updated successfully")
                if current_user.role == 'user':
                    return redirect(url_for('view_post'))
                else:
                    return redirect(url_for('all_post'))
            else:
                print("Failed to update post")
        except Exception as e:
            print(f"Error updating post: {e}")
    else:
        print("Form validation failed")
        print(form.errors)

    return render_template('edit_post_form.html', form=form, post_id=post_id)



############################################################ SUBSCRIPTION #############################################################
@app.route('/payment/<plan_id>', methods=['GET', 'POST'])
@login_required
def payment(plan_id):
    plan = api_calls.get_plan_by_id(plan_id)  # Fetch the plan details from the database or API

    if plan.fees == 0:
        return redirect(url_for('create_subscription', plan_id=plan.id))

    return render_template('payment.html', plan_id=plan_id)


@app.route('/create-subscription/<plan_id>', methods=['GET','POST'])
@login_required
def create_subscription(plan_id):
    plan = api_calls.get_plan_by_id(plan_id)  # Fetch the plan details from the database or API
    print(plan)

    if plan['fees'] == 0:
        # Directly create the subscription for free plans
        result = api_calls.start_subscription(plan_id=plan_id, stripe_token=None, access_token=current_user.id)
        if result:
            return redirect(url_for('user_dashboard'))  # Redirect to the user dashboard
        else:
            return redirect(url_for('user_view_plan'))
    else:
        # Handle paid subscriptions
        stripe_token = request.form.get('stripeToken')
        result = api_calls.start_subscription(plan_id=plan_id, stripe_token=stripe_token, access_token=current_user.id)
        if result:
            return render_template('payment_success.html')
        else:
            return render_template('payment_failure.html')


@app.route('/cancel-subscription/<subscription_id>', methods=['GET','POST'])
@login_required
def cancel_subscription(subscription_id):
    try:
        result = api_calls.cancel_subscription(subscription_id=subscription_id)
        if result:
            return redirect(url_for('profile'))

    except Exception as e:
        print(e)


@app.route('/resume-subscription/<subscription_id>', methods=['GET','POST'])
@login_required
def resume_subscription(subscription_id):
    try:
        result = api_calls.resume_subscription(subscription_id=subscription_id)
        if result:

            return redirect(url_for('profile'))

    except Exception as e:
        print(e)


@app.route('/purchase_history', methods=['GET'])
@login_required
def get_purchase_history():
    access_token = current_user.id
    purchase_data = api_calls.purchase_history(access_token)

    return render_template('purchase_history.html', purchase_data=purchase_data)

@app.route('/all-subscriptions', methods=['GET'])
@login_required
def get_all_subscriptions():
    access_token = current_user.id
    purchase_data = api_calls.get_all_subscriptions(access_token)

    return render_template('all_subscription.html', purchase_data=purchase_data)



    return render_template('all_posts.html', result=result)

@app.route('/admin/media')
@login_required
def media():

    return render_template('media.html', result=result)

@app.route('/admin/comment')
@login_required
def comment():

    return render_template('comments.html', result=result)


@app.route('/users/view-posts')
def view_post():
    result = api_calls.get_all_posts()
    response = api_calls.get_all_categories()
    if result is None:
        result = []  # Set result to an empty list

    if response is None:
        response = []
    print(result)

    return render_template('list_of_posts.html', result=result, response=response)

@app.route('/posts/<post_title>', methods=['GET', 'POST'])
def get_post(post_title):
    post_id = request.form['post_id']
    result = api_calls.get_post(post_id=post_id)
    title = result["title"]
    content = result["content"]
    author_name = result["author_name"]
    created_at = result["created_at"]

    return render_template('post.html', title=title, content=content, author_name=author_name, created_at=created_at)
################################################ CHATBOT #########################################################

@app.route('/chatbot')
def chatbot():
    return render_template('chatbot.html')


# @app.route('/send_message', methods=['POST'])
# def send_message():
#     user_input = request.form['user_input']
#     print(user_input)
#     bot_response = model.generate_content(user_input)
#     print(bot_response.text)
#     return redirect(url_for('chatbot', bot_response=bot_response.text))

@app.route('/send_message', methods=['POST'])
def send_message():
    user_input = request.form['user_input']
    print(user_input)
    bot_response = model.generate_content(user_input)
    print(bot_response.text)
    # Process user input here or send it to your chatbot backend
    # For simplicity, let's just respond with a dummy message

    return jsonify({'bot_response': bot_response.text})


###################################form builder################

@app.route('/formbuilder')
@login_required
def formbuilder():
    return render_template('formbuilder.html')


############################################# Email Templates ################################

@app.route("/email-templates/all", methods=['GET', 'POST'])
@login_required
def list_of_email_templates():
    result = api_calls.get_all_email_templates(access_token=current_user.id)
    return render_template('list_of_email_templates.html', result=result)


@app.route("/email-templates/create-template", methods=['GET', 'POST'])
def create_template():
    form = forms.CreateEmailTemplate()
    print("outside")
    if form.validate_on_submit():
        name = form.name.data
        subject = form.subject.data
        body = form.content.data
        result = api_calls.create_template(name, subject, body, access_token=current_user.id)
        print("inside")
        return redirect(url_for('list_of_email_templates'))

    return render_template('create_email_template.html', form=form)


@app.route("/email-templates/update-template/<template_id>", methods=['GET', 'POST'])
@login_required
def update_email_template(template_id):
    form = forms.UpdateEmailTemplate()
    result = api_calls.get_email_template_by_id(template_id=template_id, access_token=current_user.id)
    name = result["name"]
    subject = result["subject"]
    body = result["body"]

    if form.validate_on_submit():
        # Update user information
        name = form.name.data
        subject = form.subject.data
        body = form.content.data

        result = api_calls.edit_eamil_template(template_id=template_id,
                                                 name=name, subject=subject, body=body, access_token=current_user.id)
        return redirect(url_for('list_of_email_templates'))

    # Prefill the form fields with user information
    form.name.data = name
    form.subject.data = subject
    form.content.data = body

    return render_template('update_email_template.html', subject=subject, name=name, form=form, body=body, template_id=template_id)


@app.route("/email-templates/delete-template/<template_id>", methods=['GET', 'POST'])
@login_required
def delete_email_template(template_id):
    result = api_calls.delete_template(template_id=template_id, access_token=current_user.id)
    return redirect(url_for('list_of_email_templates'))


############################## Sending Email #####################################################

@app.route("/email-templates/<template_id>/send-mail", methods=['GET', 'POST'])
@login_required
def send_mails(template_id):
    form = forms.SendEmail()
    result = api_calls.get_email_template_by_id(template_id=template_id, access_token=current_user.id)
    subject = result["subject"]
    body = result["body"]

    if form.validate_on_submit():
        # Update user information
        to = form.to.data
        subject = form.subject.data
        body = form.content.data

        result = api_calls.send_email(to=to, subject=subject, body=body, access_token=current_user.id)
        return redirect(url_for('list_of_email_templates'))

    # Prefill the form fields with user information

    form.subject.data = subject
    form.content.data = body

    return render_template('send_emails.html', subject=subject, form=form, body=body, template_id=template_id)


@app.route("/email-settings", methods=['GET', 'POST'])
@login_required
def email_settings():
    return render_template('user_email_dashboard.html')



if __name__ == '__main__':
    app.run()


