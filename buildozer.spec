[app]
title = UYUBox
package.name = uyubox
package.domain = com.quantumkeyuyu

# Где лежит код приложения
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,ttf,otf,txt,md,json

# Версия приложения
version = 0.1.0

# ВАЖНО: cryptography закреплена <3.4, иначе потянет Rust на Android
requirements = python3,kivy==2.2.1,kivymd==1.2.0,argon2_cffi==21.3.0,openssl,cffi,cryptography<3.4,git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6

# Bootstrap
bootstrap = sdl2

# Ориентация и полноэкранный режим (можешь поменять при желании)
orientation = portrait
fullscreen = 1

# Только нужные архитектуры
android.archs = arm64-v8a,armeabi-v7a

# Целевая и минимальная версии Android SDK
android.api = 33
android.minapi = 24

# Согласованный NDK API для python-for-android
p4a.ndk_api = 24

# Локальные рецепты p4a с фиксами зависимостей
p4a.local_recipes = ./p4a-recipes

# Включаем AndroidX и авто-принятие лицензий
android.enable_androidx = True
android.accept_sdk_license = True


[buildozer]
# Уровень логов Buildozer (2 = debug, можно уменьшить до 1)
log_level = 2

# Предупреждать, если запускаешь под root
warn_on_root = 1
