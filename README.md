# English Learning App Backend

A professional, advanced, and modern Django REST API backend for English learning applications.

## 🚀 Features

- **Modern Django Structure**: Clean, modular architecture with best practices
- **Custom User Model**: Email-based authentication with comprehensive user profiles
- **REST API**: Full-featured API with JWT authentication
- **Background Tasks**: Celery integration for async processing
- **Email System**: Comprehensive email templates and verification
- **API Documentation**: Auto-generated with drf-spectacular
- **Testing**: Pytest setup with comprehensive test coverage
- **Code Quality**: Black, flake8, and pre-commit hooks
- **Production Ready**: Security configurations and monitoring

## 📁 Project Structure

```
english-learning-app-backend/
├── apps/                          # Django applications
│   ├── users/                     # User management app
│   │   ├── models.py             # User and UserProfile models
│   │   ├── serializers.py        # API serializers
│   │   ├── views.py              # API views and ViewSets
│   │   ├── urls.py               # URL patterns
│   │   ├── admin.py              # Admin interface
│   │   ├── utils.py              # Utility functions
│   │   ├── tasks.py              # Celery background tasks
│   │   └── signals.py            # Django signals
│
├── config/                        # Project configuration
│   ├── settings/                  # Django settings
│   │   ├── base.py               # Base settings
│   │   ├── development.py        # Development settings
│   │   ├── production.py         # Production settings
│   │   └── testing.py            # Testing settings
│   ├── urls.py                   # Main URL configuration
│   ├── wsgi.py                   # WSGI configuration
│   ├── asgi.py                   # ASGI configuration
│   └── celery.py                 # Celery configuration
├── templates/                     # Email templates
│   └── users/
│       └── emails/
├── static/                        # Static files
├── media/                         # User uploaded files
├── logs/                          # Application logs
├── requirements.txt               # Python dependencies
├── manage.py                      # Django management script
├── env.example                    # Environment variables example
├── .gitignore                     # Git ignore rules
└── README.md                      # Project documentation
```

## 🛠️ Installation

### Prerequisites

- Python 3.8+
- PostgreSQL (recommended) or SQLite
- Redis (for Celery)
- Virtual environment

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd english-learning-app-backend
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

5. **Run migrations**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Create superuser**
   ```bash
   python manage.py createsuperuser
   ```

7. **Run the development server**
   ```bash
   python manage.py runserver
   ```

## 🔧 Configuration

### Environment Variables

Copy `env.example` to `.env` and configure:

- `SECRET_KEY`: Django secret key
- `DEBUG`: Debug mode (True/False)
- `DATABASE_URL`: Database connection string
- `EMAIL_*`: Email configuration
- `CELERY_*`: Celery configuration
- `REDIS_URL`: Redis connection string

### Database

The project supports both PostgreSQL (recommended for production) and SQLite (development).

### Celery Setup

1. **Start Redis**
   ```bash
   redis-server
   ```

2. **Start Celery worker**
   ```bash
   celery -A config worker -l info
   ```

3. **Start Celery beat (for scheduled tasks)**
   ```bash
   celery -A config beat -l info
   ```

## 📚 API Documentation

Once the server is running, you can access:

- **Swagger UI**: http://localhost:8000/api/docs/
- **ReDoc**: http://localhost:8000/api/redoc/
- **API Schema**: http://localhost:8000/api/schema/

## 🧪 Testing

Run tests with pytest:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=apps --cov-report=html
```

## 🚀 Deployment

### Production Settings

The project includes production-ready settings with:

- Security headers
- HTTPS redirects
- Static file optimization
- Sentry integration
- Redis caching

### Docker (Recommended)

Create a `Dockerfile` and `docker-compose.yml` for containerized deployment.

## 📝 Code Quality

### Pre-commit Hooks

Install pre-commit hooks:

```bash
pre-commit install
```

### Code Formatting

Format code with Black:

```bash
black .
```

### Linting

Run flake8:

```bash
flake8 .
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions, please open an issue on GitHub.