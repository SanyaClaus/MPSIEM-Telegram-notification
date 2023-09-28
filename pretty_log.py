from datetime import datetime, timedelta


class PrettyLog:
    def __init__(self, prefix, limit=10):
        self.list = []
        self.prefix = prefix
        self.limit = limit

    def __append(self, text):
        self.list.append(text)
        if len(self.list) > self.limit:
            self.list.remove(self.list[0])

    def __str__(self):
        out = ""
        for i in self.list:
            out = out + i + '\n'
        return out

    # Логирование
    def logging(self, text):
        # timedelta - отдельная поправка на часовой пояс, если скрипт запущен не на SIEM
        log_time = datetime.now() + timedelta(hours=0)
        log_str = "{0} {1}: {2}".format(log_time, self.prefix, text)
        print(log_str)
        self.__append(text=log_str)
