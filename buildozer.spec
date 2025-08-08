[app]
title = Zilant Prime Mobile
package.name = zilant_prime_mobile
package.domain = org.zilantprime
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 0.1.0

# ВАЖНО: дублируем зависимости тут, buildozer не читает requirements.txt
requirements = python3,kivy==2.2.1,kivymd==1.2.0,argon2-cffi,cryptography,git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6

orientation = portrait
fullscreen = 0

# Разрешения
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

# API/NDK
android.api = 33
android.minapi = 24
android.ndk = 25.2.9519653
# Если в CI задаём переменные ANDROIDSDK/ANDROIDNDK — buildozer их подхватит и не будет качать

# Архитектуры
android.archs = arm64-v8a, armeabi-v7a

# Лог/отладка
log_level = 2
package.mode = debug
android.enable_androidx = True

# Значок (при желании поменяй путь)
icon.filename = 34362759-5ab3-4969-b744-d3efa2d51a9d.png

# p4a/Kivy
p4a.branch = master
p4a.bootstrap = sdl2

# Чуть чистоты
requirements.source.exclude_exts = pyc,pyo
ignore_path = .git,.github,__pycache__,*.pyc,*.pyo,.gitignore
