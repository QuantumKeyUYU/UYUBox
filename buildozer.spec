[app]
# Имя, отображаемое пользователю.
title = ZilantMobile

# Уникальное имя пакета (без пробелов). Используется в имени APK.
package.name = zilantmobile

# Домены принято указывать в обратной записи. Измените при необходимости.
package.domain = org.zilant

# Версия приложения (0.1, 1.0 и т.д.).
version = 0.1

# Каталог с исходным кодом. Buildozer будет собирать все файлы из него.
source.dir = .

# Расширения файлов, которые должны попасть в сборку.
source.include_exts = py,png,jpg,kv,atlas,json,txt

# Используемые зависимости. `python3` добавляет CPython интерпретатор.
requirements = python3,kivy,kivymd,argon2-cffi,cryptography,zilant-prime-core

# Орентация экрана.
orientation = portrait

# Не открывать приложение во весь экран (оставляем панель уведомлений).
fullscreen = 0

# Минимальная версия Android (API level). 21 соответствует Android 5.0.
android.minapi = 21

# Архитектуры, для которых будет собираться APK. arm64-v8a нужен для современных устройств.
android.archs = armeabi-v7a,arm64-v8a

# Запрашиваем только необходимые разрешения. Уберите WRITE_EXTERNAL_STORAGE, если распаковка идёт во внутреннюю память.
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

# Включаем ProGuard/Minify для обфускации и уменьшения размера APK.
android.proguard = True
android.add_proguard_rules = proguard-rules.pro

# Для сборки release необходимо включить следующую строку или добавить флаг --release к buildozer
android.release = False

# Используем папку внутреннего хранилища приложения (android/private storage)
android.private_storage = True

# Отключаем режим отладки. Параметр будет переопределён buildozer‑командой.
android.debug = False

# Указываем, что приложение может работать без доступа к Интернету.
android.internet = 0

# Не добавляем заглушку logcat.
# buildozer по умолчанию использует python activity и предоставляет logging через обычный Python

[buildozer]
# Уровень подробности логов (0 — минимально, 2 — максимально)
log_level = 1

# Каталог, куда buildozer помещает временные файлы и SDK/NDK. Измените, если необходимо.
build_dir = .buildozer

# Clean build before each run. Полезно, если вы меняли зависимости.
# clean_build = True