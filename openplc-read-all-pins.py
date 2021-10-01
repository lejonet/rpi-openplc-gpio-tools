#!/usr/bin/env python3

from __future__ import print_function
import frida
import time
import argparse
import sys

parser = argparse.ArgumentParser(description="Continuously output the values of the GPIO pins.")
parser.add_argument('process', type=str, help="The PID or process name to attach to.", default="openplc", nargs="?")
args = parser.parse_args()

session = frida.attach(args.process)

script = session.create_script("""
        var translation_table = {'0x8': '%IX0.0', '0x9': '%IX0.1', '0x7': '%IX0.2', '0x0': '%IX0.3', '0x2': '%IX0.4', '0x3': '%IX0.5', '0xc': '%IX0.6', '0xd': '%IX0.7', '0xe': '%IX1.0', '0x15': '%IX1.1', '0x16': '%IX1.2', '0x17': '%IX1.3', '0x18': '%IX1.4', '0x19': '%IX1.5', '0xf': '%QX0.0', '0x10': '%QX0.1', '0x4': '%QX0.2', '0x5': '%QX0.3', '0x6': '%QX0.4', '0xa': '%QX0.5', '0xb': '%QX0.6', '0x1a': '%QX0.7', '0x1b': '%QX1.0', '0x1c': '%QX1.1', '0x1d': '%QX1.2'};
        Interceptor.attach(Module.getExportByName(null, 'digitalWrite'), {
            onEnter: function(args) {
                send({"value": args[1], "pin": translation_table[args[0]]});
            }
        });
        Interceptor.attach(Module.getExportByName(null, 'digitalRead'), {
            onEnter: function(args) {
                this.arg0 = translation_table[args[0]];
            },
            onLeave: function(retval) {
                send({"value": retval, "pin": this.arg0});
            }
        });
        """)

outputs = {'%QX0.0': None, '%QX0.1': None, '%QX0.2': None, '%QX0.3': None, '%QX0.4': None, '%QX0.5': None, '%QX0.6': None, '%QX0.7': None, '%QX1.0': None, '%QX1.1': None, '%QX1.2': None}
inputs = {'%IX0.0': None, '%IX0.1': None, '%IX0.2': None, '%IX0.3': None, '%IX0.4': None, '%IX0.5': None, '%IX0.6': None, '%IX0.7': None, '%IX1.0': None, '%IX1.1': None, '%IX1.2': None, '%IX1.3': None, '%IX1.4': None, '%IX1.5': None}
cycle_time = time.monotonic()

def on_message(message, data):
    global cycle_time
    if message['type'] == 'error':
        print(f"[!] {message['stack']}")
    elif message['type'] == 'send':
        payload = message['payload']
        if "QX" in payload['pin']:
            outputs[payload['pin']] = payload['value']
        elif "IX" in payload['pin']:
            inputs[payload['pin']] = payload['value']

        now = time.monotonic()
        if (now - cycle_time) >= 1.0:
            print("It has gone over a second")
            print(f"Outputs:\n{outputs}")
            print(f"Inputs:\n{inputs}")
            cycle_time = now

    else:
        print(message)

print(f"Inputs: {inputs}")
print(f"Outputs: {outputs}")
script.on('message', on_message)
script.load()
sys.stdin.read()

