[app]
title = Zilant Prime Mobile
package.name = zilant_prime_mobile
package.domain = org.zilantprime
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 0.1.0

# Дублируем зависимости тут
requirements = python3,kivy==2.2.1,kivymd==1.2.0,argon2-cffi,cryptography,git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6

orientation = portrait
fullscreen = 0

android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

# API/NDK
android.api = 33
android.minapi = 24
android.ndk = 25.2.9519653
android.archs = arm64-v8a, armeabi-v7a

# ЯВНЫЕ ПУТИ SDK/NDK — чтобы Buildozer не качал свои
android.sdk_path = /usr/local/lib/android/sdk
android.ndk_path = /usr/local/lib/android/sdk/ndk/25.2.9519653

# Лог/отладка
log_level = 2
package.mode = debug
android.enable_androidx = True

# Иконка
icon.filename = 34362759-5ab3-4969-b744-d3efa2d51a9d.png

# p4a/Kivy
p4a.branch = master
p4a.bootstrap = sdl2

# Чистота пакета
requirements.source.exclude_exts = pyc,pyo
ignore_path = .git,.github,__pycache__,*.pyc,*.pyo,.gitignore
