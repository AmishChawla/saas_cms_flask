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
        response = requests.post(constants.BASE_URL + '/register', data=json.dumps(data), headers=headers)
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
