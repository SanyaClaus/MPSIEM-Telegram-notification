import time
from datetime import datetime, timedelta
import requests
import db_querys
import settings
import db
import pretty_log

# Включение логирования
logger = pretty_log.PrettyLog(prefix="Main", limit=10)
log = logger.logging

# Отключение предупреждений SSL в консоль
requests.packages.urllib3.disable_warnings()

# Переопределение кол-ва попыток для запросов по URL
requests.adapters.DEFAULT_RETRIES = 5

# Служебные переменные
bot_db_connect, bot_db_cursor = db.connection_init()  # инициализация подключения к БД бота
bearer_token = None  # хранит полученный токен для связи с SIEM
bearer_token_lifetime = None
refresh_token = None  # хранит полученный refresh_token для обновления bearer_token
chat_ids = db.DbTable(bot_db_connect, bot_db_cursor, db_querys.user_allowed_insert, db_querys.user_allowed_get,
                      db_querys.user_allowed_delete)

# хранит время последнего отправленного ботом инцидента
last_incident_time = db.DbVariable(bot_db_connect, bot_db_cursor, db_querys.last_incident_time_set,
                                   db_querys.last_incident_time_get)
# хранит номер последнего обновления из Telegram
last_update = db.DbVariable(bot_db_connect, bot_db_cursor, db_querys.last_update_set, db_querys.last_update_get)


# Авторизация
def get_bearer_token():
    url = settings.base_url + ":3334/connect/token"
    payload = "username=" + settings.username + \
              "&password=" + settings.password + \
              "&client_id=" + settings.client_id + \
              "&client_secret=" + settings.client_secret + \
              "&grant_type=password" \
              "&response_type=code%20id_token" \
              "&scope=authorization%20offline_access%20mpx.api%20ptkb.api "
    headers = {
        **settings.default_header,
        **{"Content-Type": "application/x-www-form-urlencoded",
           "Authorization": "Bearer undefined"}
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
def get_incidents(token):
    global last_incident_time
    # при первом запуске last_incident_time не установлен
    if not last_incident_time.get():
        today = datetime.now()
        last_1d = (today - timedelta(days=1)).isoformat()
        # используется заранее заданный отступ по дате (сутки)
        last_incident_time.set(last_1d)
    log("Пробую найти инциденты от {0}, текущий токен {1}".format(last_incident_time.get(), token))

    url = settings.base_url + "/api/v2/incidents/"
    # фильтр инцидентов
    payload = {
        "offset": 0,
        "limit": 50,
        "groups": {"filterType": "no_filter"},
        "timeFrom": last_incident_time.get(),
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
        **settings.default_header,
        **{"Content-Type": "application/json", "Authorization": "Bearer {0}".format(token)}
    }

    response = requests.request("POST", url, json=payload, headers=headers, verify=False)

    if response.status_code == 401:
        return 401
    return response.json()['incidents']


# Превращение инцидента в строку
def incident_to_string(incident):
    try:
        # время обрезается до формата, который удается распарсить, добавляется поправка на наш часовой пояс
        date = (datetime.fromisoformat(incident['created'][:23]) + settings.time_zone).strftime("%Y.%m.%d %H:%M:%S")
        id = incident['id']
        key = incident['key']
        severity = incident['severity']
        type = incident['type']
        name = incident['name']
        status = incident['status']
        link = f'{settings.base_url}/#/incident/incidents/view/{id}'

        # к обозначению опасности добавляю цветной эмодзи для наглядности
        if severity == "High":
            severity = "Высокая 🔴"
        elif severity == "Medium":
            severity = "Средняя 🟠"
        elif severity == "Low":
            severity = "Низкая 🟡"

        # получение событий по инциденту
        events = get_events_by_incident_id(incident_id=id)
        events_str = "\nИнцидент без событий"
        # если есть события
        if len(events) > 0:
            events_str = "\nСобытия по инциденту: \n\n"
            # распарсить события в строку events_str
            for ev in events:
                ev_date = (datetime.fromisoformat(ev['date'][:23]) + settings.time_zone).strftime("%Y.%m.%d %H:%M:%S")
                ev_description = ev['description']
                ev_str = "Дата: {0}\nСобытие: {1}".format(ev_date, ev_description)
                events_str = events_str + ev_str + "\n\n"
        result_string = f"{key}\n" \
                        f"Время: {date}\n" \
                        f"Опасность: {severity}\n" \
                        f"Тип: {type}\n" \
                        f"Имя: {name}\n" \
                        f"Статус: {status}\n" \
                        f"Ссылка на инцидент: {link}" \
                        f"\n{events_str}"
        return result_string
    except Exception as ex_parse:
        log("Ошибка при парсинге инцидента: " + str(ex_parse))
        return "Не удалось распарсить инцидент"


# Поиск событий по id инцидента
def get_events_by_incident_id(incident_id):
    url = settings.base_url + "/api/incidents/" + incident_id + "/events"
    payload = ""
    headers = {
        **settings.default_header,
        **{"Authorization": "Bearer {0}".format(bearer_token)}
    }
    response = requests.request("GET", url, data=payload, headers=headers, verify=False)
    return response.json()


# Получение новых сообщений из Телеграм
def get_telegram_updates(offset=0):
    try:
        response = requests.get("https://api.telegram.org/bot" + settings.tg_bot_token + "/getUpdates?offset="
                                + str(offset) + "&timeout=" + str(settings.tg_updates_timeout),
                                timeout=(settings.tg_updates_timeout+1, settings.tg_updates_timeout+1)
                                )
        if response.status_code == 200:
            response = response.json()
            return response
        else:
            return None
    except requests.exceptions.ConnectTimeout:
        log("Не удалось получить новые события из Телеграм (метод getUpdates) - ConnectTimeout")
    except requests.exceptions.ConnectionError:
        log("Не удалось получить новые события из Телеграм (метод getUpdates) - ConnectionError")
    except Exception as ex_tg_upd:
        log("Не удалось получить новые события из Телеграм (метод getUpdates) - {0}".format(ex_tg_upd))


# Парсинг входящих сообщений в Телеграм
def check_new_chats():
    global last_update
    log("Ожидаю сообщения в ТГ в течение {0} сек...".format(settings.tg_updates_timeout))
    updates = get_telegram_updates(last_update.get())
    if updates is None:
        log("Нет новых сообщений в ТГ.")
        return 0
    if len(updates['result']) == 0:
        log("Нет новых сообщений в ТГ.")
        return 0
    log("Обнаружены новые сообщения к боту, обработка...")
    new_chats = []
    for up in updates["result"]:
        try:
            last_update.set(up["update_id"] + 1)
            type = str(up["message"]["entities"][0]["type"])
            text = str(up["message"]["text"])
            username = up["message"]["from"]["username"]
            chat_id = up["message"]["chat"]["id"]
            log("Входящее сообщение от {0}: {1}".format(username, text))
            if (type == "bot_command") and (text == "/start"):
                new_chats.append([username, chat_id])
            elif (type == "bot_command") and ("/accept" in text[:7]):
                if chat_id == settings.admin_chat_id:
                    allow_chat_id = text[7:]
                    if allow_chat_id not in chat_ids.get():
                        if chat_ids.append(allow_chat_id):
                            # отправка сообщения администратору
                            send_telegram_message("Доступ разрешен, "
                                                  "инциденты будут отправляться в чат {0}".format(allow_chat_id))
                            # отправка сообщение новому пользователю
                            send_telegram_message("Администратор разрешил доступ к инцидентам.", [allow_chat_id])
                        else:
                            send_telegram_message("При добавлении значения в БД произошла ошибка. "
                                                  "Значение добавлено во временную переменную до перезапуска.")
                    else:
                        send_telegram_message("Доступ уже был разрешен для чата {0}".format(allow_chat_id))
            elif (type == "bot_command") and ("/deny" in text[:5]):
                if chat_id == settings.admin_chat_id:
                    deny_chat_id = text[5:]
                    if deny_chat_id in chat_ids.get():
                        chat_ids.remove(deny_chat_id)
                    # отправка сообщения администратору
                    send_telegram_message("Доступ запрещен, инциденты НЕ будут отправляться "
                                          "в чат {0}".format(deny_chat_id))
            elif (type == "bot_command") and ("/ping" in text[:10]) and chat_id in chat_ids:
                send_telegram_sticker(sticker_id=settings.ping_sticker, ids=[chat_id])
            elif (type == "bot_command") and ("/debug" in text[:6]):
                if chat_id == settings.admin_chat_id:
                    msg = f"last_incident_time = {last_incident_time.get()}\n" \
                          f"last_update = {last_update.get()}\n" \
                          f"chat_ids = {chat_ids.get()}\n" \
                          f"Последние логи: \n{logger}"
                    send_telegram_message(msg=msg)
        except KeyError:
            log("Не удалось найти один из параметров сообщения, скорее всего это была не /команда. "
                "Проблемный update: \n{0}".format(up))
            try:
                # TODO: оно одинаково реагирует на добавление в чат и удаление из чата
                chat_id = up['my_chat_member']['chat']['id']
                chat_name = up['my_chat_member']['chat']['title']
                log(f"Бот был добавлен или удален из чата {chat_id}")
                new_chats.append([chat_name, chat_id])
            except Exception:
                log("И не добавление в чат.")
            continue
        except NameError:
            log("Не удалось найти один из параметров сообщения, скорее всего это была не /команда")
            continue
    if len(new_chats):
        str_new_chats = ""
        for i in new_chats:
            str_new_chats = str_new_chats + "@{0}\n(разрешить просмотр логов /accept{1}, " \
                                            "игнорировать /deny{1}).\n".format(i[0], i[1])
        send_telegram_message("Обнаружены новые пользователи бота: \n" + str_new_chats)
    log("... обработка закончена.")


# Отправка сообщения в Телеграм
def send_telegram_message(msg, ids=[settings.admin_chat_id]):
    # Цикл отправляет сообщения всем перечисленным в ids пользователям
    for id in ids:
        try:
            response = requests.post("https://api.telegram.org/bot" + settings.tg_bot_token + "/sendMessage",
                                     data={'chat_id': id,
                                           'text': msg})
            if response.status_code == 200:
                log("В чат {0} отправлено сообщение: {1}".format(id, msg).replace("\n", " \\ "))
            else:
                log("Не удалось отправить сообщение в чат {0}. Ошибка: {1}".format(id, response).replace("\n", " \\ "))
            # Задержка нужна, чтобы не выйти за ограничения Телеграма (антиспам)
            time.sleep(0.4)
        except Exception as ex:
            log("Не удалось отправить сообщение в чат {0}: {1}".format(id, ex))


# Отправка стикера или gif-ки в Телеграм
def send_telegram_sticker(sticker_id, ids=[settings.admin_chat_id]):
    for id in ids:
        try:
            response = requests.post("https://api.telegram.org/bot" + settings.tg_bot_token + "/sendSticker",
                                     data={'chat_id': id,
                                           'sticker': sticker_id})
            if response.status_code == 200:
                log("В чат {0} отправлен стикер или гифка: {1}".format(id, sticker_id).replace("\n", " \\ "))
        except Exception as ex:
            log("Не удалось отправить стикер или гифку в чат {0}: {1}".format(id, ex))


# Основное тело скрипта
if __name__ == "__main__":
    # отправка сообщения администратору
    send_telegram_message(msg="Бот запущен.")
    work = True
    while work:
        try:
            # Запрос списка инцидентов
            incidents = get_incidents(token=bearer_token)
            # Если не авторизован (случается при первом старте и при окончании действия токена)
            if incidents == 401:  # Unauthorised
                log("Не авторизован в SIEM, авторизуюсь.")
                # Авторизоваться повторно
                if not get_bearer_token():
                    send_telegram_message(msg="Не удалось авторизоваться в SIEM: не правильный логин/пароль.")
                    raise Exception("Не правильный логин/пароль")
                continue
            # Если новые инциденты найдены
            if len(incidents) > 0:
                log("Найдены новые инциденты, пробую обработать их...")
                try:
                    send_telegram_message(msg="Новые инциденты:", ids=chat_ids.get())
                    for inc in reversed(incidents):
                        time.sleep(0.5)
                        send_telegram_message(msg=incident_to_string(inc), ids=chat_ids.get())
                        # чтобы получить в следующий раз только новые инциденты, в переменную last_incident_time
                        # устанавливается время последнего найденного инцидента + 1 миллисекунда, чтобы исключить из проверки
                        # последний инцидент
                        new_last_inc_time = (datetime.fromisoformat(inc['created'][:23])
                                             + timedelta(milliseconds=1)).isoformat() + 'Z'
                        log("Try to set last_incident_time = {0}".format(new_last_inc_time))
                        last_incident_time.set(new_last_inc_time)
                except requests.exceptions.ConnectTimeout:
                    log("Не удалось отправить сообщение в Телеграм - ConnectTimeout")
                except ValueError as ex:
                    log("Ошибка при преобразовании даты/времени инцидента: {0}".format(ex))
                except Exception as ex:
                    log(ex)
                time.sleep(settings.pause_time)
            else:
                log("Не найдено новых инцидентов")
                time.sleep(settings.pause_time)
                check_new_chats()
        except Exception as ex:
            log(ex)
            send_telegram_message(msg="Произошла непредвиденная ошибка, бот остановлен.\n{0}".format(ex))
            raise
