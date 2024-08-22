# Open Source SaaS Boilerplate built with Python, Flask and FastAPI
Open Source SaaS boilerplate with API, CMS, Membership, Subscriptions, Admin Panel and AI integration, designed to accelerate your software development process. \
Checkout demo at [SaaS Boilerplate Demo](http://35.154.190.245:5000) 
## Features
Built with Python, Flask and FastAPI, our boilerplate is designed to accelerate
your development process, ensuring scalability, flexibility, and top-notch
performance.

### FastAPI Integration
Experience the speed and simplicity of FastAPI, a modern web framework for
building APIs with Python.
FastAPI’s asynchronous capabilities enable you to create high-performance
applications that handle concurrent tasks effortlessly.

### Asynchronous Support
Our boilerplate is fully equipped with asynchronous programming support,
allowing you to build responsive and scalable applications.
This ensures your SaaS application can manage multiple requests
simultaneously without compromising on performance.
### User Authentication and Authorization
Implement robust user authentication and authorization systems out-of-the-
box.
Our boilerplate includes secure login, registration, password management, and
role-based access control to protect your application and its users.
### Database Integration
Seamlessly integrate with popular databases such as PostgreSQL, MySQL, and
SQLite.
Our boilerplate provides a flexible and efficient way to manage your
application’s data, ensuring reliability and performance.
### API Documentation with Swagger UI
Benefit from auto-generated API documentation using Swagger UI.
This feature provides a user-friendly interface for developers to explore and
test your APIs, enhancing the development experience and collaboration.
### Email and Notification System
Efficient email and notification system with built-in support for
sending emails and notifications to users.
This feature is essential for user engagement and communication within your
application.
### Admin Dashboard
Manage your application with ease using the built-in admin dashboard.
Monitor user activities, manage content, and perform administrative tasks
through a user-friendly interface.
### Security Best Practices
Our boilerplate follows security best practices, ensuring your application is
protected against common vulnerabilities.
Features such as secure password hashing, input validation, and CSRF
protection are built-in to safeguard your data and users.

## Installation
### 1. Install required libraries
`pip install requirements3.txt`

### 2. Configure `secrets.env` and `constants.py`


> [!IMPORTANT]
> Get your google keys from google console.

> [!NOTE]  
> Download this api project from [API](https://github.com/AmishChawla/saas_cms_fastapi)

_secrets.env_
```
OPEN_AI_API_KEY='your api key here'
GOOGLE_CLIENT_ID = 'your api key here'
GOOGLE_CLIENT_SECRET = 'your api key here'
REDIRECT_URI = 'your_redirect_url_here'
```

_constants.py_
```
MY_ROOT_URL = 'your_current_project_url_here'
ROOT_URL = 'your_api_url_here'
BASE_URL = '[your_api_url_here]/api'
```

### 3. Run the project
Run `python app.py` to run this project


## Documentation
[Admin Panel](documentation/admin_panel.md) \
[User Panel](documentation/user_panel.md) \
[Formbuilder](documentation/formbuilder.md) \
[Posts](documentation/posts.md) \
[Pages](documentation/pages.md) \
[Newsletter](documentation/newsletter.md) \
[Mail Setup](documentation/mail_setup.md) \
[User Site](documentation/user_site.md)
 
## Demo
Checkout the demo of the project at [SaaS Boilerplate](http://35.154.190.245:5000/login) \
Checkout our API repo at [API Repo](https://github.com/AmishChawla/saas_cms_fastapi) \
Link to our [API Docs](http://35.154.190.245:8000/docs)