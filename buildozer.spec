[app]
title = Zilant Prime Mobile
package.name = zilant_prime_mobile
package.domain = org.zilantprime
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 0.1.0
requirements = python3,kivy==2.2.1,kivymd==1.2.0,argon2-cffi,cryptography,git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6
orientation = portrait
fullscreen = 0
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.api = 33
android.minapi = 24
android.archs = arm64-v8a, armeabi-v7a
android.ndk = 25.2.9519653
android.gradle_dependencies = 
android.allow_backup = True
log_level = 2

# Если будут ошибки с SSL или cryptography — включим эти пакеты:
# (но лучше не включать без нужды, чтобы APK не раздулся)
# requirements.source = pycryptodome, cffi

# Пакуем всё в один .apk
package.mode = debug
android.enable_androidx = True

# Значки
icon.filename = 34362759-5ab3-4969-b744-d3efa2d51a9d.png

# Поддержка Kivy на Android
p4a.branch = master
p4a.bootstrap = sdl2

# Чтобы не ломались cryptography и argon2
requirements.source.exclude_exts = pyc,pyo

# Мелочи
ignore_path = .git,.github,__pycache__,*.pyc,*.pyo,.gitignore
