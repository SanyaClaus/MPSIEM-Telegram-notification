from os import path
import sqlite3
import settings
import db_querys
import pretty_log

logger = pretty_log.PrettyLog(prefix="DB", limit=10)
log = logger.logging


# Класс для переменной, хранящейся в БД
class DbVariable:
    def __init__(self, db_connection, db_cursor, db_query_set, db_query_get):
        self.db_connection = db_connection
        self.db_cursor = db_cursor
        self.db_query_set = db_query_set
        self.db_query_get = db_query_get
        self.__value = get_one(db_cursor, db_query_get)

    def set(self, value):
        self.__value = value
        try:
            insert(self.db_connection, self.db_cursor, self.db_query_set, self.__value)
        except sqlite3.Error as ex:
            log("При изменении параметра {0} в БД произошло исключение: {1}".format(self.__value, str(ex)))

    def get(self):
        return self.__value

    def __str__(self):
        return str(self.__value)


# Класс для получения таблицы, хранящейся в БД
class DbTable:
    def __init__(self, db_connection, db_cursor, db_query_append, db_query_get, db_query_del):
        self.db_connection = db_connection
        self.db_cursor = db_cursor
        self.db_query_set = db_query_append
        self.db_query_get = db_query_get
        self.db_query_del = db_query_del
        self.__list = list(get_many(db_cursor, db_query_get))
        self.index = 0  # нужен для итератора

    def get(self):
        return self.__list

    def append(self, value):
        self.__list.append(value)
        try:
            insert(self.db_connection, self.db_cursor, self.db_query_set, value)
            return True
        except sqlite3.Error as ex:
            log("При добавлении значения {0} в БД произошло исключение: {1}".format(value, str(ex)))
            return False

    def remove(self, value):
        self.__list.remove(value)
        try:
            execute_with_values(self.db_connection, self.db_cursor, self.db_query_del, value)
            return True
        except sqlite3.Error as ex:
            log("При удалении значения {0} из БД произошло исключение: {1}".format(value, str(ex)))
            return False

    def __contains__(self, value):
        return value in self.__list

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        try:
            result = self.__list[self.index]
        except IndexError:
            raise StopIteration
        self.index += 1
        return result


# Функция проверки БД бота
def check_tables(cursor):
    cursor.execute(db_querys.tables_list)
    answer = cursor.fetchall()
    log("Проверка БД бота...")
    goal = 0
    if ('tg_users_allowed',) in answer:
        log('+ таблица tg_users_allowed существует')
        goal += 1
    else:
        log('- таблица tg_users_allowed отсутствует в БД')
    if ('tg_users_denied',) in answer:
        log('+ таблица tg_users_denied существует')
        goal += 1
    else:
        log('- таблица tg_users_denied отсутствует в БД')
    if ('variables',) in answer:
        log('+ таблица variables существует')
        goal += 1
    else:
        log('- таблица variables отсутствует в БД')
    if goal == 3:
        log("БД бота готова к работе")
    else:
        raise Exception("База данных бота повреждена. Удалите файл {0} "
                        "или восстановите его вручную.".format(settings.dbFileName))


# Создать коннектор и курсор для обращения к БД
def connection_init():
    if not path.exists(settings.dbFileName):
        log("Файл с БД бота не найден")
        # создание пустого файла
        open(settings.dbFileName, "w").close()
        db_connect = sqlite3.connect(settings.dbFileName)  # settings.dbFileName)
        db_cursor = db_connect.cursor()
        db_cursor.executescript(db_querys.tables_create)
        db_cursor.close()
        log("Файл с БД бота создан")
    db_connect = sqlite3.connect(settings.dbFileName)  # settings.dbFileName)
    db_cursor = db_connect.cursor()
    check_tables(db_cursor)
    return db_connect, db_cursor


# Получить одно значение из БД
def get_one(cursor: sqlite3.Cursor, query: str):
    cursor.execute(query)
    result = cursor.fetchall()
    log("db.get_one: \nquery - {0}. \nresult - {1}".format(query, result))
    return result[0][0]


# Получить список значений из БД
def get_many(cursor: sqlite3.Cursor, query: str):
    cursor.execute(query)
    response = cursor.fetchall()
    log("db.get_one: \nquery - {0}. \nresult - {1}".format(query, response))
    try:
        # Преобразование листа с кортежами в лист без вложенности
        result = []
        for i in range(len(response)):
            result.append(response[i][0])
        return result
    except IndexError:
        log("Непредвиденная иерархия в ответе от БД: {0}".format(response))
        return response


# Вставить данные в БД
def insert(connect: sqlite3.Connection, cursor: sqlite3.Cursor, query: str, *variables):
    query = query.format(*variables)
    cursor.execute(query)
    result = cursor.fetchall()
    connect.commit()
    log("db.insert: \nquery - {0}. \nresult - {1}".format(query, result))
    return result


# Выполнить другой код с данными к БД (например, удаление)
def execute_with_values(connect: sqlite3.Connection, cursor: sqlite3.Cursor, query: str, *variables):
    query = query.format(*variables)
    cursor.execute(query)
    result = cursor.fetchall()
    connect.commit()
    log("db.executeWithValues: \nquery - {0}. \nresult - {1}".format(query, result))
    return result
