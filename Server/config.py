from socket import gethostname, getaddrinfo

PORT = 5055
FILE_PORT = 5056
SERVER = getaddrinfo(gethostname(), None)[2][4][0]
ADDR = (SERVER, PORT)
FILE_ADDR = (SERVER, FILE_PORT)
HEADER = 64
COMMANDS = ["/ban",
            "/kick",
            "/block",
            "/unblock",
            "/help",
            "/participants",
            "/get_file",
            "/preview",
            "/view_files"]
ADMIN_PASS = "admin"
NICK_MAX_LEN = 20
DOWNLOADS_FOLDER_NAME = "downloads"
FILE_CHUNK_SIZE = 16000
IMG_CROP_SIZE = (80, 40)
HELP = """Docs for commands are coming soon. Available commands:
1)/ban(admin only), 
2)/kick(admin only), 
3)/block(admin only), 
4)/unblock(admin only),
5)/help,
6)/participants,
7)/get_file,
8)/send_files,
9)/preview,
10)/view_files
"""
