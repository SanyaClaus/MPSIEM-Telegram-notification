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
requests.adapters.DEFAULT_RETRIES = 3

# Служебные переменные
bot_db_connect, bot_db_cursor = db.connection_init()  # инициализация подключения к БД бота
bearer_token = None  # хранит полученный токен для связи с SIEM
bearer_token_lifetime = None  # не используется
refresh_token = None  # хранит полученный refresh_token для обновления bearer_token
allowed_chats_ids = db.DbTable(db_connection=bot_db_connect,
                               db_cursor=bot_db_cursor,
                               db_query_append=db_querys.user_allowed_insert,
                               db_query_get=db_querys.user_allowed_get,
                               db_query_del=db_querys.user_allowed_delete)
banned_chats_ids = db.DbTable(db_connection=bot_db_connect,
                              db_cursor=bot_db_cursor,
                              db_query_append=db_querys.user_banned_insert,
                              db_query_get=db_querys.user_banned_get,
                              db_query_del=db_querys.user_banned_delete)

# хранит время последнего отправленного ботом инцидента
last_incident_time = db.DbVariable(bot_db_connect, bot_db_cursor, db_querys.last_incident_time_set,
                                   db_querys.last_incident_time_get)
# хранит номер последнего обновления из Telegram
last_update = db.DbVariable(bot_db_connect, bot_db_cursor, db_querys.last_update_set, db_querys.last_update_get)


# Авторизация
def siem_get_bearer_token():
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
def siem_get_incidents():
    global last_incident_time
    # при первом запуске last_incident_time не установлен
    if not last_incident_time.get():
        today = datetime.now()
        last_1d = (today - timedelta(days=1)).isoformat()
        # используется заранее заданный отступ по дате (сутки)
        last_incident_time.set(last_1d)
    log("Пробую найти инциденты от {0}, текущий токен {1}".format(last_incident_time.get(), bearer_token))

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
        **{"Content-Type": "application/json", "Authorization": "Bearer {0}".format(bearer_token)}
    }

    response = requests.request("POST", url, json=payload, headers=headers, verify=False)

    if response.status_code == 401:
        return 401
    return response.json()['incidents']


# Получить информацию по инциденту
def siem_get_incident_by_id(incident_id):
    url = settings.base_url + "/api/incidentsReadModel/incidents/" + str(incident_id)
    headers = {
        **settings.default_header,
        **{"Content-Type": "application/json", "Authorization": "Bearer {0}".format(bearer_token)}
    }
    response = requests.request("GET", url, headers=headers, verify=False)

    if response.status_code == 401:
        return 401
    return response.json()


# Превращение инцидента в строку
def incident_to_string(incident):
    try:
        # время обрезается до формата, который удается распарсить, добавляется поправка на наш часовой пояс
        inc_date = (datetime.fromisoformat(incident['created'][:23]) + settings.time_zone).strftime("%Y.%m.%d %H:%M:%S")
        inc_id = incident['id']
        inc_key = incident['key']
        inc_severity = incident['severity']
        inc_type = incident['type']
        inc_name = incident['name']
        inc_status = incident['status']
        inc_link = f'{settings.base_url}/#/incident/incidents/view/{inc_id}'

        # к обозначению опасности добавляю цветной эмодзи для наглядности
        if inc_severity == "High":
            inc_severity = "Высокая 🔴"
        elif inc_severity == "Medium":
            inc_severity = "Средняя 🟠"
        elif inc_severity == "Low":
            inc_severity = "Низкая 🟡"

        # получение событий по инциденту
        events = siem_get_events_by_incident_id(incident_id=inc_id)
        events_str = "\nИнцидент без событий"
        # если есть события
        if len(events) > 0:
            events_str = "\nСобытия по инциденту: \n\n"
            ev_number = 0
            # парсинг событий в строку events_str
            for ev in events:
                ev_number += 1
                ev_date = (datetime.fromisoformat(ev['date'][:23]) + settings.time_zone).strftime("%Y.%m.%d %H:%M:%S")
                ev_description = ev['description']
                ev_str = "Дата: {0}\nСобытие: {1}".format(ev_date, ev_description)
                events_str = events_str + ev_str + "\n\n"
                # если обработали нужное число событий - остановиться
                if ev_number == settings.max_events_count:
                    events_str = events_str + "И еще {0} событий.".format(len(events) - ev_number)
                    break
        result_string = f"{inc_key}\n" \
                        f"Время: {inc_date}\n" \
                        f"Опасность: {inc_severity}\n" \
                        f"Тип: {inc_type}\n" \
                        f"Имя: {inc_name}\n" \
                        f"Статус: {inc_status}\n" \
                        f"Ссылка на инцидент: {inc_link}" \
                        f"\n{events_str}"
        return result_string
    except Exception as ex_parse:
        log("Ошибка при парсинге инцидента: " + str(ex_parse))
        return "Не удалось распарсить инцидент"


# Поиск событий по id инцидента
def siem_get_events_by_incident_id(incident_id):
    url = settings.base_url + "/api/incidents/" + incident_id + "/events"
    payload = ""
    headers = {
        **settings.default_header,
        **{"Authorization": "Bearer {0}".format(bearer_token)}
    }
    response = requests.request("GET", url, data=payload, headers=headers, verify=False)
    return response.json()


# Изменить статус инцидента
def siem_set_incident_status(incident_id, status, measures=None, message=None):
    url = settings.base_url + "/api/incidents/" + incident_id + "/transitions"
    payload = {
        "id": status,
        "measures": measures,
        "message": message
    }
    headers = {
        **settings.default_header,
        **{"Authorization": "Bearer {0}".format(bearer_token)}
    }
    log("Попытка изменить инцидент, payload: {0}; header: {1}".format(payload, headers))
    response = requests.request(method="PUT", url=url, headers=headers, verify=False, json=payload)
    return response.status_code


# Получение новых сообщений из Телеграм
def tg_get_updates(offset=0):
    try:
        response = requests.get("https://api.telegram.org/bot" + settings.tg_bot_token + "/getUpdates?offset="
                                + str(offset) + "&timeout=" + str(settings.tg_updates_timeout),
                                timeout=(settings.tg_updates_timeout + 1, settings.tg_updates_timeout + 1)
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


# Добавить чат в список оповещаемых
def allow_chat(allow_chat_id):
    if allow_chat_id not in allowed_chats_ids.get():
        if allow_chat_id != '':
            if allowed_chats_ids.append(int(allow_chat_id)):
                return True, None
            else:
                return False, "При добавлении значения в БД произошла ошибка. " \
                              "Значение добавлено во временную переменную до перезапуска."
        else:
            return False, "Не указан id чата для добавления."
    else:
        return False, f"Доступ уже был разрешен для чата {allow_chat_id}"


# Заблокировать чат (не обрабатывать события из этого чата)
def ban_chat(ban_chat_id):
    if ban_chat_id not in banned_chats_ids.get():
        if ban_chat_id != '':
            if banned_chats_ids.append(int(ban_chat_id)):
                return True, None
            else:
                return False, "При добавлении значения в БД произошла ошибка. " \
                              "Значение добавлено во временную переменную до перезапуска."
        else:
            return False, "Не указан id чата для блокировки."
    else:
        return False, f"Доступ ранее уже был заблокирован для чата {ban_chat_id}"


# Парсинг входящих сообщений в Телеграм
def check_new_chats():
    global last_update
    log("Ожидаю сообщения в ТГ в течение {0} сек...".format(settings.tg_updates_timeout))
    updates = tg_get_updates(last_update.get())
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
            if 'message' in up:
                # получено сообщение
                if up['message']['from']['id'] in banned_chats_ids:
                    # игнорировать сообщение от заблокированных чатов
                    log("Проигнорировано сообщение из заблокированного чата")
                    continue
                if 'text' in up["message"]:
                    # сообщение содержит текст
                    try:
                        up_chat_id = up["message"]["chat"]["id"]
                        up_text = str(up["message"]["text"])
                        up_username = '@' + up["message"]["from"]["username"] if "username" in up["message"]["from"] \
                            else up["message"]["from"]["first_name"] if "first_name" in up["message"]["from"] \
                            else up["message"]["from"]["id"]
                        log("Входящее сообщение от {0}: {1}".format(up_username, up_text))
                        if up_text[0] == '/':
                            up_type = str(up["message"]["entities"][0]["type"])
                            if (up_type == "bot_command") and (up_text == "/start"):
                                new_chats.append([up_username, up_chat_id])
                            elif (up_type == "bot_command") and ("/accepted" in up_text[:9]):
                                accepted_list = str(db.get_many(cursor=bot_db_cursor, query=db_querys.user_allowed_get))
                                tg_send_message(msg="Список чатов, куда отправляются оповещения об "
                                                    "инцидентах: {0}".format(accepted_list))
                            elif (up_type == "bot_command") and ("/accept" in up_text[:7]):
                                if up_chat_id == settings.admin_chat_id:
                                    allow_chat_id = int(up_text[7:])
                                    result, reason = allow_chat(allow_chat_id)
                                    if result:
                                        tg_send_message(msg="Вы разрешили отправку оповещений об инцидентах в чат "
                                                            "с id {0}".format(allow_chat_id))
                                        tg_send_message(msg="Администратор открыл доступ. Оповещения об инцидентах "
                                                            "будут отправляться в этот чат.", ids=[allow_chat_id])
                                    else:
                                        tg_send_message(msg=reason)
                            elif (up_type == "bot_command") and ("/deny" in up_text[:5]):
                                if up_chat_id == settings.admin_chat_id:
                                    deny_chat_id = int(up_text[5:])
                                    if deny_chat_id in allowed_chats_ids.get():
                                        allowed_chats_ids.remove(deny_chat_id)
                                        # отправка сообщения администратору
                                        tg_send_message("Инциденты НЕ будут отправляться "
                                                        "в чат {0}".format(deny_chat_id))
                                    else:
                                        tg_send_message("Чата с id {0} нет в списке оповещаемых.".format(deny_chat_id))
                            elif (up_type == "bot_command") and ("/banned" in up_text[:9]):
                                banned_list = str(db.get_many(cursor=bot_db_cursor, query=db_querys.user_banned_get))
                                tg_send_message(msg="Список заблокированных чатов: {0}".format(banned_list))
                            elif (up_type == "bot_command") and ("/unban" in up_text[:6]):
                                if up_chat_id == settings.admin_chat_id:
                                    unban_chat_id = int(up_text[6:])
                                    log(f"Разбанить {unban_chat_id}")
                                    if int(unban_chat_id) in banned_chats_ids.get():
                                        banned_chats_ids.remove(unban_chat_id)
                                        # отправка сообщения администратору
                                        tg_send_message("Разблокирован чат {0}".format(unban_chat_id))
                                    else:
                                        tg_send_message("Чата с id {0} нет в списке "
                                                        "заблокированных.".format(unban_chat_id))
                            elif (up_type == "bot_command") and ("/ban" in up_text[:4]):
                                # TODO: забанить
                                if up_chat_id == settings.admin_chat_id:
                                    ban_chat_id = up_text[4:]
                                    # удалить из листа оповещаемых
                                    if ban_chat_id in allowed_chats_ids.get():
                                        allowed_chats_ids.remove(ban_chat_id)
                                    # добавить в лист заблокированных
                                    result, reason = ban_chat(int(ban_chat_id))
                                    if result:
                                        tg_send_message(msg="Вы заблокировали чат с id {0}.".format(allow_chat_id))
                                    else:
                                        tg_send_message(msg=reason)
                            elif (up_type == "bot_command") and ("/help" in up_text[:5]):
                                if up_chat_id == settings.admin_chat_id:
                                    help_message = "/ping - проверка работоспособности бота\n" \
                                                   "`/accept[id]` - вручную разрешить отправку оповещений об " \
                                                   "инцидентах в чат по id (например `/accept123456789`)\n" \
                                                   "/accepted - отобразить список всех чатов, куда отправляются " \
                                                   "оповещения об инцидентах\n" \
                                                   "`/deny[id]` - перестать отправлять оповещения об инцидентах в " \
                                                   "чат по id (например `/accept123456789`)\n" \
                                                   "`/ban[id]` - заблокировать чат по id: перестать обрабатывать " \
                                                   "любые события с чатом, не оповещать администратора о нем " \
                                                   "(например`/ban123456789`)\n" \
                                                   "`/unban[id]` - убрать чат из списка заблокированных " \
                                                   "(например`/ban123456789`)\n" \
                                                   "/banned - отобразить список заблокированных чатов\n" \
                                                   "/debug - получить последние логи\n"
                                    tg_send_message(msg=help_message, parse_mode="Markdown")
                            elif (up_type == "bot_command") and (
                                    "/ping" in up_text[:5]) and up_chat_id in allowed_chats_ids:
                                tg_send_sticker(sticker_id=settings.ping_sticker, ids=[up_chat_id])
                            elif (up_type == "bot_command") and ("/debug" in up_text[:6]):
                                if up_chat_id == settings.admin_chat_id:
                                    msg = f"last_incident_time = {last_incident_time.get()}\n" \
                                          f"last_update = {last_update.get()}\n" \
                                          f"chat_ids = {allowed_chats_ids.get()}\n" \
                                          f"Последние логи: \n{logger}"
                                    tg_send_message(msg=msg)
                    except KeyError:
                        log("Не удалось найти один из параметров сообщения. Проблемный update: \n{0}".format(up))
                        continue
                    except NameError:
                        log("Не удалось найти один из параметров сообщения. Проблемный update: \n{0}".format(up))
                        continue
                else:
                    log("Входящее сообщение без текста проигнорировано")

            if 'callback_query' in up:
                # получен callback от нажатия кнопки
                if up['callback_query']['from']['id'] in banned_chats_ids:
                    # игнорировать сообщение от заблокированных чатов
                    continue
                callback_id = up['callback_query']['id']
                callback_data = up['callback_query']['data']
                callback_user_id = up['callback_query']['from']['id']
                callback_username = \
                    up['callback_query']['from']['username'] if 'username' in up['callback_query']['from'] else None
                callback_message_id = up['callback_query']['message']['message_id']
                callback_chat_id = up['callback_query']['message']['chat']['id']
                log(f"Получен callback от "
                    f"пользователя {callback_username} ({callback_user_id}): {callback_data}")
                if callback_user_id in allowed_chats_ids:
                    need_update = False
                    if "apprv" in callback_data[:5]:
                        # подтвердить инцидент
                        approve_inc_id = callback_data[6:]
                        log("Попытка подтвердить инцидент {inc} пользователем {user}".format(inc=approve_inc_id,
                                                                                             user=callback_user_id))
                        measures_text = "Инцидент подтвержден через Telegram-бот."
                        message_text = "Инцидент подтвержден пользователем " \
                                       "@{username} ({userid}) через Telegram-бот.".format(username=callback_username,
                                                                                           userid=callback_user_id)
                        result = siem_set_incident_status(incident_id=approve_inc_id,
                                                          status="Approved",
                                                          measures=measures_text,
                                                          message=message_text)
                        if result == 204:
                            log("Инцидент подтвержден")
                            tg_answer_callback(callback_query_id=callback_id, text="Инцидент подтвержден")
                        else:
                            log("Ошибка при подтверждении инцидента, SIEM вернул код {0}".format(result))
                            tg_answer_callback(callback_query_id=callback_id, text="Не удалось подтвердить инцидент")
                        need_update = True
                    if "close" in callback_data[:5]:
                        # закрыть инцидент
                        close_inc_id = callback_data[6:]
                        log("Попытка закрыть инцидент {inc} пользователем {user}".format(inc=close_inc_id,
                                                                                         user=callback_user_id))
                        measures_text = "Инцидент закрыт через Telegram-бот."
                        message_text = "Инцидент закрыт пользователем " \
                                       "{username} ({userid}).".format(username=callback_username,
                                                                       userid=callback_user_id)
                        result = siem_set_incident_status(incident_id=close_inc_id,
                                                          status="Closed",
                                                          measures=measures_text,
                                                          message=message_text)
                        if result == "204":
                            log("Инцидент закрыт")
                            tg_answer_callback(callback_query_id=callback_id, text="Инцидент закрыт")
                        else:
                            log("Ошибка при закрытии инцидента: {0}".format(result))
                            tg_answer_callback(callback_query_id=callback_id, text="Не удалось закрыть инцидент")
                        need_update = True
                    if ("check" in callback_data[:5]) or need_update:
                        # обновить инфо об инциденте
                        check_inc_id = callback_data[6:]
                        incident = siem_get_incident_by_id(incident_id=check_inc_id)
                        incident_str = incident_to_string(incident)
                        text = incident_str + "\n\nИнформация обновлена в " + str(datetime.now())
                        keyboard = generate_incident_keyboard(incident=incident)
                        tg_edit_message(msg=text, chat_id=callback_chat_id,
                                        message_id=callback_message_id, reply_markup=keyboard)
                        log("В чате {0} обновлена информация об инциденте {1}".format(callback_chat_id, check_inc_id))
                        tg_answer_callback(callback_query_id=callback_id, text="Обновлена информация об инциденте")
                if callback_user_id == settings.admin_chat_id:
                    if 'accept' in callback_data[:6]:
                        accepted_chat_id = callback_data[6:]
                        result, reason = allow_chat(allow_chat_id=accepted_chat_id)
                        if result:
                            log(f"Администратор разрешил отправлять оповещения об инцидентах в чат {accepted_chat_id}")
                            text = f"Вы разрешили отправлять оповещения в чат {accepted_chat_id} {datetime.now()}"
                            tg_edit_message(msg=text, chat_id=callback_chat_id,
                                            message_id=callback_message_id)
                            tg_send_message(msg="Администратор открыл доступ. Оповещения об инцидентах "
                                                "будут отправляться в этот чат.", ids=[accepted_chat_id])
                        else:
                            tg_send_message(msg="Произошла ошибка при добавлении чата в список: {0}".format(reason))
                    elif 'ignore' in callback_data[:6]:
                        ignored_chat_id = callback_data[6:]
                        log(f"Администратор проигнорировал чат {ignored_chat_id}")
                    elif 'ban' in callback_data[:3]:
                        if callback_user_id == settings.admin_chat_id:
                            ban_chat_id = callback_data[3:]
                            result, reason = ban_chat(int(ban_chat_id))
                            if result:
                                text = f"Вы заблокировали чат с id {ban_chat_id} {datetime.now()}"
                                tg_edit_message(msg=text, chat_id=callback_chat_id, message_id=callback_message_id)
                                log(f"Администратор заблокировал чат с id {ban_chat_id}")
                            else:
                                tg_send_message(msg=reason)

            if 'my_chat_member' in up:
                if up['my_chat_member']['chat']['id'] in banned_chats_ids:
                    continue
                # добавление бота в чат или удаление из него
                if 'status' in up['my_chat_member']['new_chat_member']:
                    status = up['my_chat_member']['new_chat_member']['status']
                    if status == 'member':
                        new_chat_id = up['my_chat_member']['chat']['id']
                        new_chat_title = up['my_chat_member']['chat']['title']
                        log(f'Бот добавлен в чат {new_chat_title} ({new_chat_id})')
                        new_chats.append([new_chat_title, new_chat_id])
                    if status == 'left':
                        left_chat_id = up['my_chat_member']['chat']['id']
                        left_chat_title = up['my_chat_member']['chat']['title']
                        log(f'Бот выгнан из чата {left_chat_title} ({left_chat_id})')

        except Exception as up_parse_ex:
            log("Непредвиденная ошибка при парсинге события из Telegram: {0}".format(up_parse_ex))

    if len(new_chats):
        for new_chat in new_chats:
            new_chat_id = new_chat[1]
            new_chat_name = new_chat[0]
            new_chat_type = "групповой чат" if int(new_chat_id) < 0 else "чат с пользователем"
            new_chat_message = f"*Обнаружен новый {new_chat_type} {new_chat_name} (id {new_chat_id}).* \n" \
                               f"Разрешить отправку оповещений об инцидентах в это чат?\n" \
                               f"✅ Разрешить - отправлять оповещения об инцидентах в этот чат.\n" \
                               f"⏹ Проигнорировать - не отправлять оповещения об инцидентах в этот чат.\n" \
                               f"⛔️ Заблокировать - больше не получать запросы на доступ этого чата."
            new_chat_keyboard = generate_chat_keyboard(chat_id=new_chat_id)
            tg_send_message(msg=new_chat_message, reply_markup=new_chat_keyboard, parse_mode="Markdown")
        # tg_send_message("Обнаружены новые пользователи бота: \n" + str_new_chats)
    log("... обработка закончена.")


# Отправка сообщения в Телеграм
def tg_send_message(msg, ids=None, reply_markup=None, parse_mode=None):
    # Цикл отправляет сообщения всем перечисленным в ids пользователям
    # Если пользователь не указан, отправляет сообщение администратору
    if ids is None:
        ids = [settings.admin_chat_id]
    for id in ids:
        try:
            data = {
                'chat_id': id,
                'text': msg[:4096],
                'parse_mode': parse_mode
            }
            if reply_markup is not None:
                data.update({'reply_markup': reply_markup})
            response = requests.post("https://api.telegram.org/bot" + settings.tg_bot_token + "/sendMessage",
                                     data=data, timeout=5)
            if response.status_code == 200:
                log("В чат {0} отправлено сообщение: {1}".format(id, msg).replace("\n", " \\ "))
            else:
                log("Не удалось отправить сообщение в чат {0}. Ошибка: {1}".format(id, response).replace("\n", " \\ "))
            # Задержка нужна, чтобы не выйти за ограничения Телеграма (антиспам)
            time.sleep(0.4)
        except Exception as ex_send_tg_msg:
            log("Не удалось отправить сообщение в чат {0}: {1}".format(id, ex_send_tg_msg))


# Отправка стикера или gif-ки в Телеграм
def tg_send_sticker(sticker_id, ids=None):
    # Если пользователь не указан, отправляет сообщение администратору
    if ids is None:
        ids = [settings.admin_chat_id]
    for id in ids:
        try:
            response = requests.post("https://api.telegram.org/bot" + settings.tg_bot_token + "/sendSticker",
                                     data={'chat_id': id,
                                           'sticker': sticker_id})
            if response.status_code == 200:
                log("В чат {0} отправлен стикер или гифка: {1}".format(id, sticker_id).replace("\n", " \\ "))
        except Exception as ex_send_tg_sticker:
            log("Не удалось отправить стикер или гифку в чат {0}: {1}".format(id, ex_send_tg_sticker))


# Редактирование сообщения в Телеграм
def tg_edit_message(msg, chat_id, message_id, reply_markup=None):
    try:
        response = requests.post("https://api.telegram.org/bot" + settings.tg_bot_token + "/editMessageText",
                                 data={'chat_id': chat_id,
                                       'message_id': message_id,
                                       'text': msg,
                                       'reply_markup': reply_markup})
        if response.status_code == 200:
            log("Изменили сообщение с id {0}".format(message_id))
        else:
            log("Не удалось изменить сообщение {0}. Ошибка: {1}".format(message_id, response).replace("\n", " \\ "))
    except Exception as ex_tg_edit_message:
        log("Не удалось изменить сообщение {0}. Ошибка: {1}".format(message_id,
                                                                    ex_tg_edit_message).replace("\n", " \\ "))


def tg_answer_callback(callback_query_id, text=None, show_alert=False, url=None, cache_time=0):
    try:
        response = requests.post("https://api.telegram.org/bot" + settings.tg_bot_token + "/answerCallbackQuery",
                                 data={'callback_query_id': callback_query_id,
                                       'text': text[:199],
                                       'show_alert': show_alert,
                                       'url': url,
                                       'cache_time': cache_time
                                       })
        if response.status_code == 200:
            log("Отправлен answerCallbackQuery: {0}".format(text))
        else:
            log("Не удалось отправить answerCallbackQuery. "
                "Ошибка: {0} - {1}".format(response.status_code, response.reason).replace("\n", " \\ "))
    except Exception as ex_tg_answer_callback:
        log("Не удалось отправить answerCallbackQuery. Ошибка: {0}".format(ex_tg_answer_callback).replace("\n", " \\ "))


# Генерация клавиатуры под инцидент
def generate_incident_keyboard(incident):
    inc_id = incident['id']
    if incident['status'] == "New":
        generated_keyboard = """{"resize_keyboard": true,"inline_keyboard": [[
        {"text":"🔄 Обновить","callback_data":"check-#incident_id#"},
        {"text":"▶️ Подтвердить","callback_data":"apprv-#incident_id#"},
        {"text":"⏹ Закрыть","callback_data":"close-#incident_id#"}
        ]]}""".replace("#incident_id#", inc_id)
    else:
        generated_keyboard = """{"resize_keyboard": true,"inline_keyboard": [[
        {"text":"🔄 Обновить информацию","callback_data":"check-#incident_id#"}
        ]]}""".replace("#incident_id#", inc_id)
    return generated_keyboard


# Генерация клавиатуры под инцидент
def generate_chat_keyboard(chat_id):
    generated_keyboard = """{"resize_keyboard": true,"inline_keyboard": [[
    {"text":"✅ Разрешить","callback_data":"accept#chat_id#"}],
    [{"text":"⏹ Проигнорировать","callback_data":"ignore#chat_id#"},
    {"text":"⛔️ Заблокировать","callback_data":"ban#chat_id#"}]]}""".replace("#chat_id#", str(chat_id))
    return generated_keyboard


# Основное тело скрипта
if __name__ == "__main__":
    # отправка сообщения администратору
    tg_send_message(msg="Бот запущен.")
    work = True
    while work:
        try:
            # Запрос списка инцидентов
            incidents = siem_get_incidents()
            # Если не авторизован (случается при первом старте и при окончании действия токена)
            if incidents == 401:  # Unauthorised
                log("Не авторизован в SIEM, авторизуюсь.")
                # Авторизоваться повторно
                if not siem_get_bearer_token():
                    tg_send_message(msg="Не удалось авторизоваться в SIEM: не правильный логин/пароль.")
                    raise Exception("Не правильный логин/пароль")
                continue
            # Если новые инциденты найдены
            if len(incidents) > 0:
                log("Найдены новые инциденты, пробую обработать их...")
                try:
                    tg_send_message(msg="Новые инциденты:", ids=allowed_chats_ids.get())
                    for inc in reversed(incidents):
                        time.sleep(0.5)
                        inc_id = inc["id"]
                        keyboard = generate_incident_keyboard(incident=inc)
                        tg_send_message(msg=incident_to_string(inc), ids=allowed_chats_ids.get(), reply_markup=keyboard)
                        # чтобы получить в следующий раз только новые инциденты, в переменную last_incident_time
                        # устанавливается время последнего найденного инцидента + 1 миллисекунда, чтобы исключить
                        # из проверки последний инцидент
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
            tg_send_message(msg="Произошла непредвиденная ошибка, бот остановлен.\n{0}".format(ex))
            raise
