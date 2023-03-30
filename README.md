# MPSIEM-Telegram-notification

Отправка инцидентов из MaxPatrol SIEM 10 в Telegram бот.

Написано для версии 26.0.4827.


client_secret для авторизации скрипта в SIEM можно взять в конфигурации Core (/var/lib/deployed-roles/mp10-application/core-##########/install.sh)

tg_bot_token для работы бота можно получить у бота всех ботов (https://t.me/BotFather)

Для получения chat_id можно написать своему боту любое сообщение, затем перейти по ссылке вида https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getUpdates, где 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 это токен вашего бота Телеграм, там вы найдете chat/id.

Запуск скрипта возможен как на удаленной машине, так и на машине с SIEM.
