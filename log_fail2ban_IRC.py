import irc.bot
import irc.strings
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import ssl
import time
import re
import queue
import threading
import os

class LogHandler(FileSystemEventHandler):
    def __init__(self, irc_bot, log_file):
        self.irc_bot = irc_bot
        self.log_file = log_file
        self.last_position = 0
        self.process_last_lines(5)

    def process_last_lines(self, num_lines):
        """ Process the last `num_lines` lines from the log file """
        with open(self.log_file, 'rb') as f:
            f.seek(0, os.SEEK_END)
            end_position = f.tell()
            lines = []
            buffer_size = 1024
            while end_position > 0 and len(lines) < num_lines:
                to_read = min(buffer_size, end_position)
                end_position -= to_read
                f.seek(end_position)
                buffer = f.read(to_read)
                lines = buffer.split(b'\n') + lines
                lines = lines[-num_lines:]
            for line in lines:
                if line:
                    line = line.decode('utf-8').strip()
                    if any(keyword in line for keyword in ["NOTICE", "Ban", "Unban", "Restore Ban"]):
                        formatted_message = self.format_message(line)
                        self.irc_bot.queue_message(formatted_message)

    def on_modified(self, event):
        if event.src_path == self.log_file:
            with open(self.log_file, 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()

            # Send all relevant lines to the IRC channel with a custom prefix
            for line in new_lines:
                if any(keyword in line for keyword in ["NOTICE", "Ban", "Unban", "Restore Ban"]):
                    formatted_message = self.format_message(line.strip())
                    self.irc_bot.queue_message(formatted_message)

    def format_message(self, log_entry):
        match = re.search(r'(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2},\d{3}) (?P<component>\S+)\s+\[(?P<id>\d+)\]: (?P<level>\S+)\s+\[(?P<jail>\w+)\]\s+(?P<action>.+)', log_entry)
        if match:
            date = match.group('date')
            time = match.group('time')
            component = match.group('component')
            id_ = match.group('id')
            level = match.group('level')
            jail = match.group('jail')
            action = match.group('action')
            # Separate Action part cleanly
            action_part = f"Action: {action.split()[0]} IP: {action.split()[-1]}"
            return (f'\x0303FROM FAIL2BAN\x03 -> \x0303Date\x03: {date} \x0303Time\x03: {time} \x0303Fail2Ban\x03: {component} '
                    f'\x0303ID\x03: [{id_}] \x0303Level\x03: {level} \x0303Jail\x03: [{jail}] \x0303{action_part}')
        return log_entry  # Fallback in case the regex doesn't match

class IRCBot(irc.bot.SingleServerIRCBot):
    def __init__(self, channel, nickname, server, port, log_file, use_ssl=False):
        ssl_factory = irc.connection.Factory(wrapper=ssl.wrap_socket) if use_ssl else irc.connection.Factory()
        irc.bot.SingleServerIRCBot.__init__(self, [(server, port)], nickname, nickname, connect_factory=ssl_factory)
        self.channel = channel
        self.log_file = log_file
        self.message_queue = queue.Queue()
        self._stop_event = threading.Event()

        # Start the thread that sends messages from the queue
        self.sender_thread = threading.Thread(target=self.send_messages_from_queue)
        self.sender_thread.start()

    def on_welcome(self, connection, event):
        connection.join(self.channel)

    def on_join(self, connection, event):
        if irc.strings.lower(event.target) == irc.strings.lower(self.channel):
            self.queue_message("Log monitor bot has joined the channel.")

    def queue_message(self, message):
        self.message_queue.put(message)

    def send_messages_from_queue(self):
        while not self._stop_event.is_set():
            try:
                message = self.message_queue.get(timeout=1)
                if self.connection.is_connected():
                    self.connection.privmsg(self.channel, message)
                time.sleep(1)  # Delay to prevent flooding
            except queue.Empty:
                continue

    def disconnect(self, message=""):
        self._stop_event.set()
        self.sender_thread.join()
        super().disconnect(message)

if __name__ == "__main__":
    channel = "#services"  # IRC channel to join
    nickname = "syslog"  # Bot's nickname
    server = "irc.tchatzone.fr"  # Replace with your IRC server
    port = 6697  # Use the SSL port
    log_file = "/var/log/fail2ban.log"  # Log file to monitor
    use_ssl = True  # Enable SSL

    bot = IRCBot(channel, nickname, server, port, log_file, use_ssl)

    event_handler = LogHandler(bot, log_file)
    observer = Observer()
    observer.schedule(event_handler, path=log_file, recursive=False)
    observer.start()

    try:
        bot.start()
    except KeyboardInterrupt:
        observer.stop()
        bot.disconnect()
    observer.join()
