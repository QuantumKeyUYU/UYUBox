[app]
title = Zilant Prime Mobile
package.name = zilant_prime_mobile
package.domain = org.zilantprime
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 0.1.0

# ВАЖНО: фиксированные версии, которые собираются на Android
requirements = python3,kivy==2.2.1,kivymd==1.2.0,argon2_cffi==21.3.0,cryptography==3.4.7,git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6

orientation = portrait
fullscreen = 0
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

android.api = 33
android.minapi = 24
android.ndk = 25.2.9519653
android.archs = arm64-v8a, armeabi-v7a

# Используем заранее установленные SDK/NDK
android.sdk_path = /usr/local/lib/android/sdk
android.ndk_path = /usr/local/lib/android/sdk/ndk/25.2.9519653

log_level = 2
package.mode = debug
android.enable_androidx = True

icon.filename = 34362759-5ab3-4969-b744-d3efa2d51a9d.png

# ВАЖНО: свежие рецепты p4a
p4a.branch = develop
p4a.bootstrap = sdl2

requirements.source.exclude_exts = pyc,pyo
ignore_path = .git,.github,__pycache__,*.pyc,*.pyo,.gitignore
