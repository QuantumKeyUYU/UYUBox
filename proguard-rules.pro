# ProGuard rules for ZilantMobile

# Сохраняем критические классы Kivy/PythonActivity. Без этого ProGuard может удалить классы,
# необходимые для запуска Python-интерпретатора в Android.
-keep class org.kivy.android.PythonActivity { *; }
-keep class org.kivy.android.PythonService { *; }
-keep class org.kivy.android.** { *; }

# Не обфусцируем классы Chaquopy (если используется), чтобы избежать проблем
# с рефлексией. Buildozer использует Chaquopy для интеграции Python.
-dontwarn com.chaquo.python.**
-keep class com.chaquo.python.** { *; }

# Сохраняем классы JSON-библиотеки.
-keep class org.json.** { *; }

# Удаляем вызовы Log.* из сборки release. Это уменьшает размер и скрывает сообщения.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}