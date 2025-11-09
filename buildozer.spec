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
requirements = python3,kivy==2.3.0,kivymd==1.2.0,cffi==1.16.0,argon2-cffi==23.1.0,cryptography<3.4,androidstorage4kivy

# Bootstrap
bootstrap = sdl2

# Ориентация и полноэкранный режим (можешь поменять при желании)
orientation = portrait
fullscreen = 1

# Только нужные архитектуры
android.archs = arm64-v8a,armeabi-v7a

# Целевая и минимальная версии Android SDK
android.api = 31
android.minapi = 21

# Версия NDK
android.ndk = 25b

# Локальные рецепты p4a с фиксами зависимостей
p4a.local_recipes = ./p4a-recipes

# Включаем AndroidX и авто-принятие лицензий
android.enable_androidx = True
android.accept_sdk_license = True
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,READ_MEDIA_AUDIO,READ_MEDIA_IMAGES,READ_MEDIA_VIDEO
android.logcat_filters = *:S python:D libc:D ActivityManager:I AndroidRuntime:E
android.python_debuggable = 1


[buildozer]
# Уровень логов Buildozer (2 = debug, можно уменьшить до 1)
log_level = 2

# Предупреждать, если запускаешь под root
warn_on_root = 1
