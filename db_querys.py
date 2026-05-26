# # # # # # # # # # # # # # # # # # # #
# Типовые запросы к базе данных бота  #
# # # # # # # # # # # # # # # # # # # #

tables_create = """
CREATE TABLE "tg_users_allowed" (
	"id"	INTEGER NOT NULL UNIQUE,
	"tg_id"	INTEGER NOT NULL UNIQUE,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE "tg_users_denied" (
	"id"	INTEGER NOT NULL UNIQUE,
	"tg_id"	INTEGER NOT NULL UNIQUE,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE "variables" (
	"id"	INTEGER NOT NULL UNIQUE,
	"name"	TEXT NOT NULL UNIQUE,
	"value"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);
INSERT INTO "main"."variables" ("name") VALUES ('last_incident_time');
INSERT INTO "main"."variables" ("name") VALUES ('last_update');"""

tables_list = """SELECT name FROM sqlite_master WHERE type='table';"""

user_allowed_insert = """INSERT INTO "main"."tg_users_allowed" ("tg_id") VALUES ('{0}');"""

user_allowed_get = """SELECT tg_id FROM tg_users_allowed;"""

user_allowed_delete = """DELETE FROM tg_users_allowed WHERE tg_id='{0}';"""

user_banned_insert = """INSERT INTO "main"."tg_users_denied" ("tg_id") VALUES ('{0}');"""

user_banned_get = """SELECT tg_id FROM tg_users_denied;"""

user_banned_delete = """DELETE FROM tg_users_denied WHERE tg_id='{0}';"""

last_incident_time_get = """SELECT value FROM variables WHERE name='last_incident_time';"""

last_incident_time_set = """UPDATE variables set value = "{0}" WHERE name = 'last_incident_time';"""

last_update_get = """SELECT value FROM variables WHERE name='last_update';"""

last_update_set = """UPDATE variables set value = "{0}" WHERE name = 'last_update';"""
