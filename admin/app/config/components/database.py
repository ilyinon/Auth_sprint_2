DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("ADMIN_DB_NAME", "content"),
        "USER": os.environ.get("PG_USER", "auth"),
        "PASSWORD": os.environ.get("PG_PASSWORD", "secret"),
        "HOST": os.environ.get("PG_HOST", "127.0.0.1"),
        "PORT": os.environ.get("PG_PORT", 5432),
        "OPTIONS": {
            # Нужно явно указать схемы, с которыми будет работать приложение.
            "options": os.environ.get("SQL_OPTIONS", "-c search_path=public,content")
        },
    }
}
