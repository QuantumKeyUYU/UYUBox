[app]
# -----------------------------------------------------------------------------
# ОСНОВНЫЕ ПАРАМЕТРЫ ПРИЛОЖЕНИЯ
# -----------------------------------------------------------------------------
title = Zilant Mobile
package.name = zilantmobile
package.domain = org.quantumkey
source.dir = .
source.include_exts = py,png,jpg,kv,ttf,txt,md
version = 0.1
entrypoint = main.py
orientation = portrait
fullscreen = 0

# -----------------------------------------------------------------------------
# ЗАВИСИМОСТИ PYTHON
# -----------------------------------------------------------------------------
# Версии зафиксированы для стабильной сборки.
requirements = \
    kivy==2.3.0,\
    kivymd==1.2.0,\
    cryptography==41.0.7,\
    argon2-cffi==23.1.0,\
    cffi==1.16.0,\
    git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6

# -----------------------------------------------------------------------------
# РАЗРЕШЕНИЯ ANDROID
# -----------------------------------------------------------------------------
android.permissions = READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE

# -----------------------------------------------------------------------------
# ПАРАМЕТРЫ СБОРКИ ANDROID
# -----------------------------------------------------------------------------
# Пути к SDK и NDK будут взяты из переменных окружения в GitHub Actions.
android.api = 34
android.minapi = 21
android.build_tools_version = 34.0.0
# ИСПРАВЛЕНИЕ: Используем NDK версии r25c, чтобы избежать ошибки SyntaxError
android.ndk = 25c
android.accept_sdk_license = True
arch = arm64-v8a, armeabi-v7a

# -----------------------------------------------------------------------------
# ОПТИМИЗАЦИЯ
# -----------------------------------------------------------------------------
p4a.branch = release-2024.01.21
copy_libs = 1