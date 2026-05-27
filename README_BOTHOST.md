# Загрузка на Bothost

## Что загружать в GitHub
Загружай содержимое этой папки:
- bot.py
- config.json
- requirements.txt
- README_RU.md
- README_BOTHOST.md
- папку data с .gitkeep

Не загружай:
- .env
- .venv
- __pycache__
- data/bot.sqlite3, если не хочешь переносить старую статистику через Git

## Bothost
Поля:
- Платформа: Discord
- Библиотека: Python / discord.py
- Git URL: ссылка на репозиторий
- Ветка: main
- Главный файл: bot.py
- Start command: python bot.py

Переменная окружения:
- DISCORD_TOKEN = токен Discord-бота

Если Bothost сам создаёт BOT_TOKEN из поля Bot Token, бот тоже его поймёт.


## Если в профиле квадратики вместо русского текста
В версии v4.2 добавлен расширенный поиск шрифтов и fallback через matplotlib/DejaVu Sans. Убедись, что Bothost переустановил зависимости из `requirements.txt`, где есть `matplotlib>=3.8.0`.
