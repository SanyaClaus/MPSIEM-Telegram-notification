import time
import requests
import urllib.parse
from datetime import datetime, timedelta

# Отключение предупреждений SSL в консоль
requests.packages.urllib3.disable_warnings()

# Настройки
pause_time = 15  # время в секундах между проверками инцидентов
time_zone = timedelta(hours=5)  # поправка на часовой пояс +5 GMT
username = "your_username"  # имя пользоватея в SIEM
password = urllib.parse.quote("Your_P@ssw0rd")  # пароль пользователя в SIEM
client_id = "mpx"
client_secret = "a123b456-c789-cdef-ghij-k81234567890"  # secret пользователя в SIEM
base_url = "https://siem.domain.local"  # url для входа в SIEM
tg_bot_token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"  # токен Телеграм-бота
chat_id = 123456789  # id чата в Телеграм

# Служебные переменные
bearer_token = None  # хранит полученный токен для связи с SIEM
bearer_token_lifetime = None
refresh_token = None  # хранит полученный refresh_token для обновления bearer_token
last_incident_time = None  # хранит время последнего отправленного ботом инцидента


# Логирование
def log(text):
    log_time = datetime.now()+timedelta(hours=0)  # Отдельная поправка на часовой пояс, если скрипт запущен не на SIEM
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


# Обновление токена, не используется
def get_bearer_refresh_token():
    global bearer_token, refresh_token
    url = base_url + ":3334/connect/token"
    payload = "username=" + username + "&password=" + password + "&client_id=" + client_id + "&client_secret=" + \
              client_secret + "&grant_type=refresh_token&response_type=code%20id_token&refresh_token=" + refresh_token
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer undefined"
    }

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)

    if response.text.find("access_token"):
        json_response = response.json()
        bearer_token = json_response["access_token"]
        refresh_token = json_response["refresh_token"]
    return bearer_token


# Получение списка инцидентов
def get_incidents(bearer_token):
    global last_incident_time
    today = datetime.now()
    last_1d = (today - timedelta(days=1)).isoformat()
    last_3d = (today - timedelta(days=3)).isoformat()
    last_7d = (today - timedelta(days=7)).isoformat()
    last_14d = (today - timedelta(days=14)).isoformat()
    # при первом запуске last_incident_time не установлен
    if not last_incident_time:
        # используется заранее заданный отступ по дате
        last_incident_time = last_1d
    log("Try to find incidents from time {0}, token {1}".format(last_incident_time, bearer_token))

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
        "User-Agent": "python-requests/2.28.1",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "Authorization": "Bearer {0}".format(bearer_token)
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
        # return date + " - " + incident['type'] + " - " + incident['name']
    except Exception as ex:
        print("Something wrong in parsing")
        print(str(ex))
        return "Incident parse error"


# Найти события по id инцидента
def get_events_by_incident_id(incident_id):
    url = base_url + "/api/incidents/" + incident_id + "/events"
    payload = ""
    headers = {
        "User-Agent": "python-requests/2.28.1",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Authorization": "Bearer {0}".format(bearer_token)
    }

    response = requests.request("GET", url, data=payload, headers=headers, verify=False)
    return response.json()


def send_telegram_message(msg):
    response = requests.post("https://api.telegram.org/bot" + tg_bot_token + "/sendMessage",
                             data={'chat_id': chat_id,
                                   'text': msg})
    if response.status_code == 200:
        log("В чат {0} отправлено сообщение: {1}".format(chat_id, msg).replace("\n", " \\ "))


# Основное тело скрипта
send_telegram_message(msg="Бот запущен.")
work = True
while work:
    # get_bearer_refresh_token()
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
        log("New incidents found, try to send it to TG")
        send_telegram_message(msg="Новые инциденты:")
        for inc in reversed(incidents):
            send_telegram_message(msg=incident_to_string(inc))
            # чтобы получить в следующий раз только новые инциденты, в переменную last_incident_time
            # устанавливается время последнего найденного инцидента + 1 миллисекунда, чтобы исключить из проверки
            # последний инцидент
            last_incident_time = (
                    datetime.fromisoformat(inc['created'][:23]) + timedelta(milliseconds=1)).isoformat()
        time.sleep(pause_time)
    else:
        log("No new incidents found")
        time.sleep(pause_time)
