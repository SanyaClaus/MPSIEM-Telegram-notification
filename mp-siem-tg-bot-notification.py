import time
import requests
from datetime import datetime, timedelta
import settings

# Отключение предупреждений SSL в консоль
requests.packages.urllib3.disable_warnings()

# Переопределение кол-ва попыток для запросов по URL
requests.adapters.DEFAULT_RETRIES = 5

# Импорт настроек
pause_time = settings.pause_time
time_zone = settings.time_zone
username = settings.username
password = settings.password
client_id = settings.client_id
client_secret = settings.client_secret
base_url = settings.base_url
tg_bot_token = settings.tg_bot_token
admin_chat_id = settings.admin_chat_id
chat_ids = settings.chat_ids
default_header = settings.default_header
ping_sticker = settings.ping_sticker
tg_updates_timeout = settings.tg_updates_timeout

# Служебные переменные
bearer_token = None  # хранит полученный токен для связи с SIEM
bearer_token_lifetime = None
refresh_token = None  # хранит полученный refresh_token для обновления bearer_token
last_incident_time = None  # хранит время последнего отправленного ботом инцидента
last_update = None  # хранит номер последнего обновления из Telegram


# Логирование
def log(text):
    log_time = datetime.now() + timedelta(hours=0)  # Отдельная поправка на часовой пояс, если скрипт запущен не на SIEM
    print("{0} {1}".format(log_time, text))


# Авторизация
def get_bearer_token():
    url = base_url + ":3334/connect/token"
    payload = "username=" + username + "&password=" + password + "&client_id=" + client_id + "&client_secret=" + \
              client_secret + "&grant_type=password&response_type=code%20id_token&scope=authorization" \
                              "%20offline_access%20mpx.api%20ptkb.api "
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer undefined"
    }

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)

    global bearer_token, refresh_token, bearer_token_lifetime
    if 'invalid_username_or_password' in response.text:
        log("Auth error: invalid_username_or_password")
        return 0
    if "access_token" in response.text:
        json_response = response.json()
        bearer_token = json_response["access_token"]
        bearer_token_lifetime = json_response["expires_in"]
        refresh_token = json_response["refresh_token"]
        log("Авторизация пройдена")
    return bearer_token


# Получение списка инцидентов
def get_incidents(bearer_token):
    global last_incident_time
    today = datetime.now()
    last_1d = (today - timedelta(days=1)).isoformat()
    # при первом запуске last_incident_time не установлен, запрашиваются все инциденты за сутки
    if not last_incident_time:
        # используется заранее заданный отступ по дате
        last_incident_time = last_1d
    log("Пробую найти инциденты от {0}, текущй токен {1}".format(last_incident_time, bearer_token))

    url = base_url + "/api/v2/incidents/"
    # фильтр инцидентов
    payload = {
        "offset": 0,
        "limit": 50,
        "groups": {"filterType": "no_filter"},
        "timeFrom": last_incident_time,
        "timeTo": None,
        "filterTimeType": "creation",
        "filter": {
            "select": ["key", "name", "category", "type", "status", "created", "assigned"],
            "orderby": [
                {
                    "field": "created",
                    "sortOrder": "descending"
                },
                {
                    "field": "status",
                    "sortOrder": "ascending"
                },
                {
                    "field": "severity",
                    "sortOrder": "descending"
                }
            ]
        },
        "queryIds": ["all_incidents"]
    }
    headers = {
        **default_header,
        **{"Content-Type": "application/json", "Authorization": "Bearer {0}".format(bearer_token)}
    }

    response = requests.request("POST", url, json=payload, headers=headers, verify=False)

    if response.status_code == 401:
        return 401
    return response.json()['incidents']


# Превращение инцидента в строку
def incident_to_string(incident):
    try:
        # время обрезается до формата, который удается распарсить, добавляется поправка на наш часовой пояс
        date = (datetime.fromisoformat(incident['created'][:23]) + time_zone).strftime("%Y.%m.%d %H:%M:%S")
        id = incident['id']
        key = incident['key']
        severity = incident['severity']
        type = incident['type']
        name = incident['name']
        status = incident['status']

        # к обозначению опасности добавляю цветной эмодзи для наглядности
        if severity == "High":
            severity = "Высокая 🔴"
        elif severity == "Medium":
            severity = "Средняя 🟠"
        elif severity == "Low":
            severity = "Низкая 🟡"

        # получение событий по инциденту
        events = get_events_by_incident_id(incident_id=id)
        events_str = "\nИнцедент без событий"
        # если есть события
        if len(events) > 0:
            events_str = "\nСобытия по инциденту: \n\n"
            # распарсить события в строку events_str
            for ev in events:
                date = (datetime.fromisoformat(ev['date'][:23]) + time_zone).strftime("%Y.%m.%d %H:%M:%S")
                description = ev['description']
                ev_str = "Дата: {0}\nСобытие: {1}".format(date, description)
                events_str = events_str + ev_str + "\n\n"

        return "{4}\nВремя: {0}\nОпасность: {5}\nТип: {1}\nИмя: {2}\nСтатус: {3}" \
               "\n{6}".format(date, type, name, status, key, severity, events_str)
    except Exception as ex:
        log("Ошибка при парсинге инцидента: " + str(ex))
        return "Не удалось распарсить инцидент"


# Поиск событий по id инцидента
def get_events_by_incident_id(incident_id):
    url = base_url + "/api/incidents/" + incident_id + "/events"
    payload = ""
    headers = {
        **default_header,
        **{"Authorization": "Bearer {0}".format(bearer_token)}
    }
    response = requests.request("GET", url, data=payload, headers=headers, verify=False)
    return response.json()


# Получение новых сообщений из Телеграм
def get_telegram_updates(offset=0):
    global tg_updates_timeout
    try:
        response = requests.get("https://api.telegram.org/bot" + tg_bot_token + "/getUpdates?offset=" + str(offset) +
                                "&timeout=" + str(tg_updates_timeout),
                                timeout=(tg_updates_timeout, tg_updates_timeout))
        if response.status_code == 200:
            response = response.json()
            return response
        else:
            return None
    except requests.exceptions.ConnectTimeout as ex:
        log("Не удалось получить новые события из Телеграм (метод getUpdates) - ConnectTimeout")
    except requests.exceptions.ConnectionError as ex:
        log("Не удалось получить новые события из Телеграм (метод getUpdates) - ConnectionError")


# Парсинг входящих сообщений в Телеграм
def check_new_chats():
    global last_update
    log("Ожидаю сообщения в ТГ в течение {0} сек...".format(tg_updates_timeout))
    updates = get_telegram_updates(last_update)
    if updates is None:
        log("Нет новых сообщений в ТГ.")
        return 0
    if len(updates['result']) == 0:
        log("Нет новых сообщений в ТГ.")
        return 0
    log("Обнаружены новые сообщения к боту, обработка...")
    for up in updates["result"]:
        new_chats = []
        try:
            last_update = up['update_id'] + 1
            type = str(up['message']['entities'][0]['type'])
            text = str(up["message"]["text"])
            username = up["message"]["from"]["username"]
            chat_id = up["message"]["chat"]["id"]
            log("Входящее сообщение от {0}: {1}".format(username, text))
            if (type == "bot_command") and (text == "/start"):
                new_chats.append([username, chat_id])
            elif (type == "bot_command") and ("/accept" in text[:7]):
                if chat_id == admin_chat_id:
                    allow_chat_id = text[7:]
                    if allow_chat_id not in chat_ids:
                        chat_ids.append(allow_chat_id)
                        # отправка сообщения администратору
                        send_telegram_message("Доступ разрешен, инциденты будут отправляться " \
                                              "в чат {0}".format(allow_chat_id))
                        # отправка сообщение новому пользователю
                        send_telegram_message("Администратор разрешил доступ к инцидентам.", [allow_chat_id])
                    else:
                        send_telegram_message("Доступ уже был разрешен для чата {0}".format(allow_chat_id))
            elif (type == "bot_command") and ("/deny" in text[:5]):
                if chat_id == admin_chat_id:
                    deny_chat_id = text[5:]
                    if deny_chat_id in chat_ids:
                        chat_ids.remove(deny_chat_id)
                    # отправка сообщения администратору
                    send_telegram_message("Доступ запрещен, инциденты НЕ будут отправляться "
                                          "в чат {0}".format(deny_chat_id))
            elif (type == "bot_command") and ("/ping" in text[:10]) and chat_id in chat_ids:
                send_telegram_sticker(sticker_id=ping_sticker, ids=[chat_id])
        except KeyError:
            continue
        if len(new_chats):
            str_new_chats = ""
            for i in new_chats:
                str_new_chats = str_new_chats + "@{0}\n(разрешить просмотр логов /accept{1}, " \
                                                "игнорировать /deny{1}).\n".format(i[0], i[1])
            send_telegram_message("Обнаружены новые пользователи бота: \n" + str_new_chats)
    log("... обработка закончена.")


# Отправка сообщения в Телеграм
def send_telegram_message(msg, ids=[admin_chat_id]):
    for id in ids:
        try:
            response = requests.post("https://api.telegram.org/bot" + tg_bot_token + "/sendMessage",
                                     data={'chat_id': id,
                                           'text': msg})
            if response.status_code == 200:
                log("В чат {0} отправлено сообщение: {1}".format(id, msg).replace("\n", " \\ "))
            time.sleep(0.5)
        except Exception as ex:
            log("Не удалось отправить сообщение в чат {0}: {1}".format(id, ex))


# Отправка стикера или gif-ки в Телеграм
def send_telegram_sticker(sticker_id, ids=[admin_chat_id]):
    for id in ids:
        try:
            response = requests.post("https://api.telegram.org/bot" + tg_bot_token + "/sendSticker",
                                     data={'chat_id': id,
                                           'sticker': sticker_id})
            if response.status_code == 200:
                log("В чат {0} отправлен стикер или гифка: {1}".format(id, sticker_id).replace("\n", " \\ "))
        except Exception as ex:
            log("Не удалось отправить стикер или гифку в чат {0}: {1}".format(id, ex))


# Основное тело скрипта
if __name__ == "__main__":
    send_telegram_message(msg="Бот запущен.")
    work = True
    while work:
        try:
            incidents = get_incidents(bearer_token=bearer_token)
            # Если Unauthorised (случается при первом старте и при окончании действия токена)
            if incidents == 401:
                log("Не авторизован в SIEM, авторизуюсь.")
                # Авторизоваться повторно
                if not get_bearer_token():
                    send_telegram_message(msg="Не удалось авторизоваться в SIEM: не правильный логин/пароль.")
                    raise Exception("Не правильный логин/пароль")
                continue
            if len(incidents) > 0:
                log("Найдены новые инциденты, пробую обработать их...")
                try:
                    send_telegram_message(msg="Новые инциденты:", ids=chat_ids)
                    for inc in reversed(incidents):
                        time.sleep(0.5)
                        send_telegram_message(msg=incident_to_string(inc), ids=chat_ids)
                        # чтобы получить в следующий раз только новые инциденты, в переменную last_incident_time
                        # устанавливается время последнего найденного инцидента + 1 миллисекунда, чтобы исключить из проверки
                        # последний инцидент
                        last_incident_time = (datetime.fromisoformat(inc['created'][:23])
                                              + timedelta(milliseconds=1)).isoformat()
                except requests.exceptions.ConnectTimeout:
                    log("Не удалось отправить сообщение в Телеграм - ConnectTimeout")
                time.sleep(pause_time)
            else:
                log("Не найдено новых инцидентов")
                time.sleep(pause_time)
                check_new_chats()
                # time.sleep(pause_time)
        except Exception as ex:
            log(ex)
