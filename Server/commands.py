from config import *
import threading
from prevw import prevw
from os import walk

incorrect_usage_msg = "Please read how to use this command before using it. Use /help"


def admin_access(func):
    def wrapper(server, params, nickname, isadmin):
        if not isadmin:
            server.send(server.clients[nickname],
                        "Access denied. Only available for admins", server.encryptors[server.clients[nickname]])
            return
        func(server, params, nickname)
    return wrapper


def help(server, params, nickname, isadmin):

    conn = server.clients[nickname]
    server.send(conn, server.help_msg, server.encryptors[conn])


@admin_access
def ban(server, params, nickname):

    conn = server.clients[nickname]

    if len(params) != 1:
        server.send(conn, incorrect_usage_msg, server.encryptors[conn])
        return

    if params[0] not in server.clients:
        server.send(conn, "No such client.", server.encryptors[conn])
        return

    banned_conn = server.clients[params[0]]

    server.banned.append(banned_conn.getpeername()[0])
    # write to file
    server.f_bans.write(banned_conn.getpeername()[0]+";")
    server.f_bans.flush()

    print(f"{nickname} banned {params[0]}")
    server.send(
        banned_conn, f"You were banned by the {nickname}", server.encryptors[server.clients[params[0]]])
    server.send_to_all(f"{nickname} banned {params[0]}")
    banned_conn.close()


@admin_access
def kick(server, params, nickname):

    conn = server.clients[nickname]

    if len(params) != 1:
        server.send(conn, incorrect_usage_msg, server.encryptors[conn])
        return

    kick_nick = params[0]

    if kick_nick not in server.clients:
        server.send(conn, "No such client.", server.encryptors[conn])
        return

    server.send(server.clients[kick_nick],
                f"You were kicked by the {nickname}.", server.encryptors[server.clients[kick_nick]])
    server.clients[kick_nick].close()
    try:
        del server.encryptors[server.clients[kick_nick]]
        del server.clients[kick_nick]
    except KeyError:
        pass

    server.send_to_all(f"{params[0]} was kicked by the {nickname}")
    print(f"{params} was kicked by the {nickname}")


@admin_access
def block(server, params, nickname):

    conn = server.clients[nickname]

    if len(params) != 1:
        server.send(conn, incorrect_usage_msg, server.encryptors[conn])
        return

    server.blocked.append(params[0])

    server.send_to_all(f"{nickname} blocked {params[0]}")
    print(f"{nickname} blocked {params[0]}")


@admin_access
def unblock(server, params, nickname):

    conn = server.clients[nickname]

    if len(params) != 1:
        server.send(conn, incorrect_usage_msg, server.encryptors[conn])
        return

    try:
        server.blocked.remove(params[0])
    except ValueError:
        server.send(conn, "this participant won't blocked",
                    server.encryptors[conn])
    else:
        server.send_to_all(f"{nickname} unblocked {params[0]}")


def participants(server, params, nickname, isadmin):

    conn = server.clients[nickname]
    participants = " ".join(list(server.clients.keys()))
    server.send(conn, participants, server.encryptors[conn])


def get_file(server, params, nickname, isadmin):

    conn = server.clients[nickname]

    if len(params) != 1:
        server.send(conn, incorrect_usage_msg, server.encryptors[conn])
        return

    threading.Thread(target=server.f_sock.send,
                     args=(nickname, params[0])).start()


def preview(server, params, nickname, isadmin):

    conn = server.clients[nickname]

    if len(params) != 1:
        server.send(conn, incorrect_usage_msg, server.encryptors[conn])
        return

    prev = prevw(params[0])
    prev = f"\n[PREVIEWING {params[0]}]\n[START]\n" + prev + "\n[END]"
    server.send(conn, prev, server.encryptors[conn])


def view_files(server, params, nickname, isadmin):
    conn = server.clients[nickname]

    files_list = "\n".join(list(walk(DOWNLOADS_FOLDER_NAME))[0][2])
    server.send(conn, "Now available files: \n" +
                files_list, server.encryptors[conn])
