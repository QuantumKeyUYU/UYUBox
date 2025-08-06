[app]
# (str) Title of your application
title = Zilant Mobile
# (str) Package name
package.name = zilantmobile
# (str) Package domain (reverse DNS notation)
package.domain = com.quantumkeyuyu
# (str) Source entry point folder
source.dir = .
# (str) Source file extensions to include
source.include_exts = py,png,kv,json
# (str) Application versioning (method 1)
version = 0.1

# (list) Application requirements
requirements = \
    kivy>=2.2.0, \
    kivymd>=1.2.0, \
    argon2-cffi>=23.1.0, \
    cryptography>=42.0.0, \
    git+https://github.com/QuantumKeyUYU/zilant-prime-core.git@v0.1.6

# (str) Presplash and icon (если есть картинки)
# presplash.filename = %(source.dir)s/data/logo.png
# icon.filename = %(source.dir)s/data/icon.png

[buildozer]
# (int) Log level (0=silent, 1=error, 2=warning, 3=info, 4=debug)
log_level = 2
# (bool) Warning about running as root
warn_on_root = False

[app:android]
# (str) Android entry point, default is main.py
entrypoint = main.py

# (list) Permissions
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

# (int) Android API to compile against
android.api = 31
# (int) Minimum Android API required
android.minapi = 21
# (str) NDK version to use
android.ndk = 25.2.9519653
# (bool) Make a release version by default? (False=debug)
android.release = False

# (bool) Enable ProGuard / minify
android.proguard = True
# (str) Path to additional ProGuard rules
android.add_proguard_rules = proguard-rules.pro

# (str) Logcat filters
android.logcat_filters = *:S python:D

# (bool) Disable Android backup
android.allow_backup = False
