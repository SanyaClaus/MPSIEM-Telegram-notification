from datetime import timedelta
import urllib.parse  # нужно для корректной отправки паролей со спецсимволами

# # # # # # #
# Настройки #
# # # # # # #

# Файл с БД бота
dbFileName = r"C:\Users\Test\PythonScripts\MPSIEM-Telegram-notification\bot.db"

# Время в секундах между проверками инцидентов
pause_time = 3

# Часовой пояс для показа времени инцидентов пользователям (3 - Москва)
time_zone = timedelta(hours=3)

# Имя пользователя в SIEM
username = "siemlogin"

# Пароль пользователя в SIEM
password = urllib.parse.quote("SI3M-P@$$w0rd")

# ID клиента в SIEM
client_id = "mpx"

# secret пользователя в SIEM
client_secret = "cccccccc-dddd-3333-4444-eeeeeeeeeeee"

# URL для входа в SIEM
base_url = "https://siem.local"

# Токен Телеграм-бота
tg_bot_token = "0123456789:AAAAAAAAAAAAAAAAAAA_BCDEFGHIJKLMNOP"

# Время в секундах на ожидание новых событий в Телеграм-боте
tg_updates_timeout = 10

# ID чата с администратором в Телеграм
admin_chat_id = 123456789

# Header по умолчанию при обращениях к SIEM
default_header = {
    "User-Agent": "python-tg-bot",
    "Accept-Encoding": "gzip, deflate",
    "Accept": "*/*"
}

# file_id или ссылка на GIF для команды /ping
ping_sticker = 'https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExMWEzNTNjNTY3MDBlZmNlZWVjYzlmODQwYTE2OGI3NWI1OWQ2O' \
               'DQ2MiZlcD12MV9pbnRlcm5hbF9naWZzX2dpZklkJmN0PWc/20xGDkXD1EUDewVjXi/giphy.gif'
