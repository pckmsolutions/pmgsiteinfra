'''
Web Channel ID

Click on the channel you want and see the url displayed on your browser.

If it's a private group then the url must be similar to:

https://web.telegram.org/#/im?p=c1018013852_555990343349619165

If this is the case, then the channel ID would be 1018013852. It's important to know that channel's IDs are always negative and 13 characters long! So add -100 to it, making the correct ID -1001018013852.
'''

from telegram.ext import Updater
from logging import Handler, LogRecord
import copy

def send_message(bot, channel, message):
    t_updater = Updater(bot, use_context=True)
    t_updater.bot.send_message(channel, message[:4096])

class LogHandler(Handler):
    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        super(LogHandler, self).__init__()

    def emit(self, record):
        send_message(self.bot_token, self.chat_id, record.getMessage())
