[app]
title = UYUBox
package.name = uyubox
package.domain = com.quantumkeyuyu
source.dir = .
source.include_exts = py,kv,png,jpg,ttf,ttc,otf,txt,json,ini,md
version = 0.1.0

# Главный модуль
entrypoint = main.py

# Kivy
requirements = \
    python3, \
    kivy==2.2.1, \
    kivymd==1.2.0, \
    # низкоуровневые зависимости для крипты
    libffi, \
    cffi==1.15.1, \
    openssl, \
    cryptography==3.4.7, \
    argon2_cffi==21.3.0, \
    git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6

# Архитектуры (новый ключ!)
android.archs = arm64-v8a, armeabi-v7a

# Минимальный API, чтобы собрать cffi/openssl стабильно
android.api = 33
android.minapi = 24
android.ndk_api = 24

# Зафиксируем инструменты (aidl и пр.)
android.build_tools_version = 30.0.3

# Путь к SDK/NDK (в раннере GitHub Actions мы так их и ставим)
android.sdk_path = /usr/local/lib/android/sdk
android.ndk_path = /usr/local/lib/android/sdk/ndk/25.2.9519653

# Используем bootstrap sdl2
android.bootstrap = sdl2

# Разрешения по необходимости
android.permissions = INTERNET

# Отключаем компиляцию .pyc из поставки
p4a.local_recipes = 
p4a.branch = master

# Логи подетальнее
log_level = 2

# Иконка/сплэш при желании:
# icon.filename = resources/icon.png
# presplash.filename = resources/presplash.png

[buildozer]
log_level = 2
warn_on_root = 1
