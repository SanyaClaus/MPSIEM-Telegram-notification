# MPSIEM-Telegram-notification

Отправка инцидентов из MaxPatrol SIEM 10 в Telegram бот.

Написано для версии 26.0.4827.

![alt text](https://github.com/SanyaClaus/MPSIEM-Telegram-notification/blob/main/preview.png?raw=true)

## Настройки

В файле ```settings.py``` находятся настройки бота:

- pause_time - время в секундах между проверками инцидентов
- time_zone - часовой пояс (в SIEM события хранятся с временем по GMT+0, соответсвенно для отображения времени по Москве нужно задать +3 часа)
- username - имя пользоватея в SIEM
- password - пароль пользователя в SIEM
- client_id - идентификатор приложения (mpx, ptkb)
- client_secret - ключ доступа к приложению в SIEM
- base_url - url для входа в SIEM
- tg_bot_token - токен Телеграм-бота
- admin_chat_id - id чата с администратором в Телеграм
- chat_ids - лист с id чатов в Телеграм, куда отсылать уведомления об инцидентах
- default_header - заголовок запросов, с которыми будет обращаться бот к SIEM


client_secret для авторизации скрипта в SIEM можно взять в конфигурации Core (*/var/lib/deployed-roles/mp10-application/core-##########/install.sh*)

tg_bot_token для работы бота можно получить у https://t.me/BotFather

Для получения chat_id можно написать своему боту любое сообщение, затем перейти по ссылке вида *https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getUpdates*, где *123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11* это токен вашего бота Телеграм, там вы найдете chat/id.

## Запуск

Запуск скрипта возможен как на удаленной машине, так и на машине с SIEM.

Для запуска скрипта запустите файл ```mp-siem-tg-bot-notification.py```

Для запуска по SSH рекомендую использовать следующую команду: 
```nohup python3 mp-siem-tg-bot-notification.py &```
