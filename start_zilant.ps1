# Запусти этот скрипт в папке с проектом (C:\Users\User\zilant-prime-core)
Write-Host "🚀 [ZILANT Prime™] Автоматический старт проекта..."

# 1. Чистим старое окружение (если нужно)
if (Test-Path ".venv") {
    Remove-Item ".venv" -Recurse -Force
    Write-Host "🧹 Удалено старое виртуальное окружение .venv"
}

# 2. Создаем и активируем новое .venv
python -m venv .venv
Write-Host "🌱 Создано новое виртуальное окружение .venv"
& .\.venv\Scripts\Activate.ps1

# 3. Ставим зависимости по modern-way
pip install -e .[dev]
Write-Host "📦 Установлены зависимости через pyproject.toml (extras: dev)"

# 4. Линтеры и форматтеры
pre-commit run --all-files
ruff check src tests
black --check src tests
mypy src
Write-Host "🧹 Линтеры, форматтеры и mypy завершены"

# 5. Генерируем SBOM и проверяем на уязвимости
syft packages . -o cyclonedx-json=sbom.json
grype sbom:sbom.json --fail-on medium
Write-Host "🔒 SBOM создан и уязвимости проверены"

# 6. Прогоняем тесты и покрытие
pytest --maxfail=1 --disable-warnings -q
pytest --cov=src/uyubox_core --cov-report=term-missing --cov-report=html:htmlcov --cov-report=xml:coverage.xml
Write-Host "✅ Тесты и покрытие завершены!"

Write-Host "🎉 [ZILANT Prime™] Проект полностью готов к работе! Добро пожаловать!"
