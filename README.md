## ⚙️ Installation
### 1. Clone the repository
```bash
git clone git@github.com:AnnaKilimova/drf_auth.git
```
### 2. Navigate to the project folder:
```bash
cd drf_auth
```
### 3. Create and activate a virtual environment
#### For MacOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate    
```  
#### For Windows:
```bash
venv\Scripts\activate    
```
### 4. Install dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt    
```
This installs all required packages listed in requirements.txt, ensuring your environment matches the project dependencies.

### 5. Apply migrations:
```bash
python manage.py migrate
```
## 🧩 Task Description
It is necessary to write a DRF application that will provide endpoints based on existing applications and a custom JWT authentication class, and implement a token refresh method. The token should expire every 5 minutes by default, but this value should be specified in the settings. ‘Attach’ the new authentication to the endpoints.

Provide a link to Git with the implemented functionality and screenshots from POSTMAN/ Web UI showing an access error without a token, token acquisition and token refresh, successful access to the endpoint with a token, an error for an expired token, successful token refresh, and a successful response with a new token.

### 🙋‍♂️ Create superuser
```bash
python manage.py createsuperuser
```
### 🚀 Running the Application
Start the server:
```bash
python manage.py runserver
```
The project will be available at:
```bash
👉 http://127.0.0.1:8000/
```
Available routes:
- [/admin/](http://127.0.0.1:8000/admin/) — Django admin panel
- [/token/](http://127.0.0.1:8000/token/) — Obtaining access + refresh tokens
- [/token/refresh/](http://127.0.0.1:8000/token/refresh/) — Updating the access token
- [/protected/](http://127.0.0.1:8000/protected/) — Secure endpoint (access token required)
Stop the server:
```bash
^C
```