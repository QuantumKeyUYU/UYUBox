[app]
title = UYUBox
package.name = uyubox
package.domain = com.quantumkeyuyu
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,ttf,otf,txt,md,json
version = 0.1.0

requirements = python3,kivy==2.2.1,kivymd==1.2.0,argon2_cffi==21.3.0,openssl,cffi,"cryptography<3.4",git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6  # <3.4: p4a bootstrap без Rust
bootstrap = sdl2

# важный фикс: только android.archs
android.archs = arm64-v8a, armeabi-v7a

android.api = 33
android.minapi = 24

# согласованный ndk api
p4a.ndk_api = 24
# локальные рецепты python-for-android с фиксами зависимостей
p4a.local_recipes = ./p4a-recipes
# при желании зафиксировать NDK:
# android.ndk = 25.2.9519653

log_level = 2
android.enable_androidx = True
android.accept_sdk_license = True
