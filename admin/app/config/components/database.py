DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('POSTGRES_USER'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD'),
        'HOST': os.environ.get('SQL_HOST', '127.0.0.1'),
        'PORT': os.environ.get('SQL_PORT', 5432),
        'OPTIONS': {
            # Нужно явно указать схемы, с которыми будет работать приложение.
            'options': os.environ.get('SQL_OPTIONS', '-c search_path=public,content')
        }
    }
}
