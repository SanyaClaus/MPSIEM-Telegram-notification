from datetime import timedelta
import urllib.parse  # нужно для корректной отправки паролей со спецсимволами

# настройки
pause_time = 15  # время в секундах между проверками инцидентов
time_zone = timedelta(hours=3)  # поправка на часовой пояс GMT+3 (Москва)
username = "user"  # имя пользоватея в SIEM
password = urllib.parse.quote("P@ssw0rd")  # пароль пользователя в SIEM
client_id = "mpx"  # идентификатор приложения
client_secret = "a123b456-c789-cdef-ghij-k81234567890"  # ключ доступа к приложению в SIEM
base_url = "https://siem.domen.local"  # url для входа в SIEM
tg_bot_token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"  # токен Телеграм-бота
admin_chat_id = 123456789  # id чата с администратором в Телеграм
chat_ids = [123456789, 234567890]  # id чатов в Телеграм
default_header = {
        "User-Agent": "python-tg-bot",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*"
}
