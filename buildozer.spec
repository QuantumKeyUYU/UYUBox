[app]
title = UYUBox
package.name = uyubox
package.domain = com.quantumkeyuyu
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,ttf,otf,txt,md,json
version = 0.1.0

# Kivy bootstrap
requirements = python3,kivy==2.2.1,kivymd==1.2.0,argon2_cffi==21.3.0,openssl,cryptography==3.4.7,git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6

# SDL2 bootstrap для Kivy
bootstrap = sdl2

# Архитектуры. В логах ругалось на старый ключ — используем новый.
android.archs = arm64-v8a, armeabi-v7a

# API уровни
android.api = 33
android.minapi = 24

# Если нужен targetSdkVersion явно:
# android.target = 33

# p4a настройки
p4a.local_recipes = 
p4a.ndk_api = 24
# если хочешь форсировать NDK 25.x (хорошо дружит с p4a 2024.06.02):
# android.ndk = 25.2.9519653

# Gradle
# android.gradle_dependencies = 
# android.gradle_version = 8.4
# android.gradle_plugin_version = 8.2.2

# Пермишены по необходимости
# android.permissions = INTERNET

# Если нужны Java сервисы/антивирусы — оставим пустым
# android.add_src = 

# Иконки/сплэш при желании
# icon.filename = %(source.dir)s/data/icon.png
# presplash.filename = %(source.dir)s/data/presplash.png

# Опции сборки
log_level = 2
warn_on_root = 1
# ускорение сборки
android.enable_androidx = True
android.accept_sdk_license = True

# Релизные подписи можно добавить позже
# [buildozer]
# ... (оставляем по умолчанию)
