[app]
title = Zilant Mobile
package.name = zilantmobile
package.domain = org.quantumkey
source.dir = .
source.include_exts = py,png,jpg,kv,ttf,txt,md
# ваш entrypoint
entrypoint = main.py
orientation = portrait
fullscreen = 1

# ─── Пакеты Python / C-рецепты ────────────────────────────────────────────
requirements = \
    kivy>=2.2.0,\
    kivymd>=1.2.0,\
    argon2-cffi>=23.1.0,\
    cryptography>=42.0.0,\
    git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6

# ─── Версии Android-SDK ───────────────────────────────────────────────────
# *pin* — без превью. Совпадает с тем, что кладём в workflow.
android.api = 34
android.minapi = 21
android.build_tools_version = 34.0.0
android.accept_sdk_license = True          # ← главное, чтоб не спрашивал

# NDK та же, что p4a считает «рекомендуемой» сейчас
android.ndk = 25.2.9519653

# ─── Унификация сборки ───────────────────────────────────────────────────
# чтоб p4a не тянул случайные master-версии
p4a.branch = release-2024.01.21

# архитектуры
arch = arm64-v8a, armeabi-v7a

# уменьшает apk: не таскаем лишние .py
copy_libs = 1

# ─── Release-сборка (если понадобится) ───────────────────────────────────
# android.release = True
# presplash.filename = data/android_presplash.png
# icon.filename     = data/icon.png
