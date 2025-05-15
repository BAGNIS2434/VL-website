# Video Library Project

A Flask web application for managing YouTube videos with timestamped annotations.

## Features

- User authentication system
- YouTube video integration
- Timestamped annotations
- Profile management
- Responsive design
- Password reset functionality

## Installation

1. Clone the repository:
```bash
git clone <your-repository-url>
cd Website
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create .env file with required environment variables:
```
FLASK_APP=src/app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
DATABASE_URL=sqlite:///instance/database.db

# Mail Settings
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

## Running Locally

Start the development server:
```bash
flask run
```
The application will be available at `http://localhost:5000`

## Deployment on Render

1. Create a Render account at render.com

2. Connect your GitHub repository

3. Create a new Web Service with these settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn src.app:create_app()`

4. Add environment variables in Render dashboard:
   - SECRET_KEY
   - JWT_SECRET_KEY
   - DATABASE_URL
   - FLASK_ENV=production
   - MAIL_USERNAME
   - MAIL_PASSWORD
   - MAIL_DEFAULT_SENDER

## Project Structure

```
Website/
├── src/
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── uploads/
│   ├── templates/
│   ├── models/
│   ├── app.py
│   └── config.py
├── instance/
├── migrations/
├── requirements.txt
├── render.yaml
└── .env
```

## Contributing

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License.
