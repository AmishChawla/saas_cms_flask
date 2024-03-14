import json
import requests
import constants


def user_login(email, password):
    print('trying2')
    data = {
        "username": email,
        "password": password
    }

    try:
        response = requests.post(constants.BASE_URL + '/login', data=data)
        print(response.text)
        print(constants.BASE_URL + '/login')
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def dashboard(file_list, access_token: str):
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        response = requests.post(constants.BASE_URL + '/process-resume/', files=file_list, headers=headers)
        return response

    except requests.exceptions.RequestException as e:
        # Handle request errors
        print(f"Error: {e}")


def user_register(username, email, password):
    print('trying3')
    headers = {'Content-Type': 'application/json'}
    data = {
        "username": username,
        "email": email,
        "password": password,
        "role": "user"
        }


    try:
        response = requests.post(constants.BASE_URL+f'/register', data=json.dumps(data), headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")

def admin_register(username, email, password):
    print('trying9')
    headers = {'Content-Type': 'application/json'}
    data = {
        "username": username,
        "email": email,
        "password": password,
        "role": "admin"
    }

    try:
        # response = requests.post(constants.BASE_URL + '/register', data=json.dumps(data), headers=headers)
        response = requests.post(constants.BASE_URL+'/register-admin', data=json.dumps(data), headers=headers)

        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def get_user_profile(access_token: str):
    headers = {'Authorization': f'Bearer {access_token}'}

    try:
        response = requests.get(constants.BASE_URL + '/user-profile', headers=headers)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def get_all_users(access_token: str):
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        response = requests.get(constants.BASE_URL + '/admin/users', headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")

def admin_login(email, password):
    print('trying3')
    data = {
        "username": email,
        "password": password
    }

    try:
        response = requests.post(constants.BASE_URL + '/admin/login', data=data)
        print(response.text)
        print(constants.BASE_URL + '/admin/login')

        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


# Endpoint only accessible to admin
def add_user(username, email, password, role, access_token: str):
    print('trying3')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    data = {
        "username": username,
        "email": email,
        "password": password,
        "role": role
    }

    try:
        response = requests.post(constants.BASE_URL + '/admin/add-user', data=json.dumps(data), headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_delete_user(access_token: str, user_id: int):
    headers = {'Authorization': f'Bearer {access_token}'}

    try:
        response = requests.delete(constants.BASE_URL + f'/admin/delete-user/{user_id}', headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_get_any_user(access_token: str, user_id: int):
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        response = requests.get(constants.BASE_URL + f'/admin/view-user/{user_id}', headers=headers)
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def update_user_password(current_password, new_password, confirm_new_password, access_token: str):
    print('trying3')
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-type': 'application/json'

    }

    data = {
        "current_password": current_password,
        "new_password": new_password,
        "confirm_new_password": confirm_new_password
    }

    try:
        response = requests.put(constants.BASE_URL + '/update-password', params=data, headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def forgot_password(email):
    print('trying6')

    headers = {
        'Content-type': 'application/json'
    }
    data = {
        "email": email,
    }

    try:
        response = requests.post(constants.BASE_URL + '/forgot-password', params=data, headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def reset_password(token, new_password):
    print('trying7')

    headers = {
        'Content-type': 'application/json'
    }
    data = {
        "token": token,
        "new_password": new_password
    }

    try:
        response = requests.post(constants.BASE_URL + '/reset-password', params=data, headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_edit_any_user(access_token: str, user_id: int, username, role, status):
    print("trying")
    headers = {'Authorization': f'Bearer {access_token}'}

    data = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "status": status
    }

    try:
        print("try")
        response = requests.put(constants.BASE_URL + f'/admin/edit-user', headers=headers, params=data)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def user_update_profile(access_token: str, username, email, profile_picture):
    print("working")
    headers = {'Authorization': f'Bearer {access_token}'}

    data = {

        "username": username,
        "email": email,

    }

    files = {
        "profile_picture": profile_picture
    }

    try:
        print("try")
        response = requests.put(constants.BASE_URL + f'/update-profile', files=files, headers=headers, data=data)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")






def get_companies():

    try:
        response = requests.get(constants.BASE_URL + f'/companies')
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def get_company_details(company_id: int):

    try:
        response = requests.get(constants.BASE_URL + f'/companies/{company_id}')
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")

def company_register(name, location, access_token):
    print('trying3')
    headers = {'Authorization': f'Bearer {access_token}'}
    params = {
        "name": name,
        "location": location,

        }
    try:
        response = requests.post(constants.BASE_URL+f'/companies/create-company', params=params, headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")



def services():
    try:
        response = requests.get(constants.BASE_URL + '/services/all-services')
        return response

    except requests.exceptions.RequestException as e:
        # Handle request errors
        print(f"Error: {e}")


def add_service(name, description):
    headers = {
        'Content-Type': 'application/json',
    }

    params = {
        "name": name,
        "description": description,
    }

    try:
        response = requests.post(constants.BASE_URL + '/services/create-service', params=params, headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_delete_service(service_id: int):

    try:
        response = requests.delete(constants.BASE_URL + f'/services/delete-service/{service_id}')
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_get_any_service(service_id: int):
    try:
        response = requests.get(constants.BASE_URL + f'/services/{service_id}')
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_edit_any_service(service_id, service_name, service_description):
    print("trying")

    data = {
        "name": service_name,
        "description": service_description
    }

    try:
        print("try")
        response = requests.put(constants.BASE_URL + f'/services/update-service/{service_id}',  json=data)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")



def admin_get_resume_history():

    try:
        response = requests.get(constants.BASE_URL + '/admin/resume-history')
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_get_all_companies():
    print("trying")
    try:
        print("try")
        response = requests.get(constants.BASE_URL + '/companies/')
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")



def trash(access_token: str):
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        response = requests.get(constants.BASE_URL + '/admin/deleted-users', headers=headers)
        print(response.text)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")

def admin_delete_company(company_id: int):
    try:
        response = requests.delete(constants.BASE_URL + f'/companies/delete-company/{company_id}')
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_get_any_company(company_id: int):
    try:
        response = requests.get(constants.BASE_URL + f'/companies/{company_id}')
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")

def admin_edit_any_company(company_id, name, location):
    print("trying")

    data = {
        "name": name,
        "location": location
    }

    try:
        print("try")
        response = requests.put(constants.BASE_URL + f'/companies/update-company/{company_id}',  params=data)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_get_email_setup(access_token: str):
    headers = {'Authorization': f'Bearer {access_token}'}
    try:
        print("try")
        response = requests.get(constants.BASE_URL + f'/smtp_settings/', headers=headers)
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")

import requests

def admin_update_email_setup(access_token: str, smtp_server, smtp_port, smtp_username, smtp_password, sender_email):
    headers = {'Authorization': f'Bearer {access_token}'}
    data = {
        "smtp_server": smtp_server,
        "smtp_port": smtp_port,
        "smtp_username": smtp_username,
        "smtp_password": smtp_password,
        "sender_email": sender_email
    }

    try:
        response = requests.put(constants.BASE_URL + f'/admin/update-email-settings/', headers=headers, json=data)
        response.raise_for_status() # Raises an HTTPError if the response was unsuccessful
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
        raise # Re-raise the exception to be handled by the caller
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
        raise # Re-raise the exception to be handled by the caller
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
        raise # Re-raise the exception to be handled by the caller
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")
        raise # Re-raise the exception to be handled by the caller


def admin_assign_service(user_id, service_ids: list):

    params = {
        "user_id": user_id

    }


    try:
        response = requests.post(constants.BASE_URL + f'/users/assign_services/', params=params, json=service_ids)
        response.raise_for_status() # Raises an HTTPError if the response was unsuccessful
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
        raise # Re-raise the exception to be handled by the caller
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
        raise # Re-raise the exception to be handled by the caller
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
        raise # Re-raise the exception to be handled by the caller
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")
        raise # Re-raise the exception to be handled by the caller


def user_specific_services(user_id):

    try:
        print("try")
        response = requests.get(constants.BASE_URL + f'/users/{user_id}/services')
        return response
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


############################################################### PLANS ##############################################################################
def get_all_plans():
    try:
        response = requests.get(constants.BASE_URL + '/plans/')
        if response.status_code == 200:
            result = response.json()
            return result

    except requests.exceptions.RequestException as e:
        # Handle request errors
        print(f"Error: {e}")


def create_plan(plan_name, time_period, fees, num_resume_parse):
    headers = {
        'Content-Type': 'application/json',
    }

    data = {
        "plan_type_name": plan_name,
        "time_period": time_period,
        "fees": fees,
        "num_resume_parse": num_resume_parse
    }

    try:
        response = requests.post(constants.BASE_URL + '/plans/create-plan', json=data, headers=headers)
        if response.status_code == 200:
            return response.json
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def delete_plan(plan_id: int):
    try:
        response = requests.delete(constants.BASE_URL + f'/plans/delete-plan/{plan_id}')
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def admin_get_any_plan(plan_id: int):
    try:
        response = requests.get(constants.BASE_URL + f'/plans/{plan_id}')
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")


def update_plan(plan_id: int, plan_name: str, time_period: str, fees: int, num_resume_parse: str):
    data = {
        "plan_type_name": plan_name,
        "time_period": time_period,
        "fees": fees,
        "num_resume_parse": num_resume_parse
    }
    try:
        print("try")
        response = requests.put(constants.BASE_URL + f'/plans/update-plan/{plan_id}',  json=data)
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred: {err}")

