#!/usr/bin/env python3

from __future__ import print_function
import frida
import argparse

parser = argparse.ArgumentParser(description="Get or set a GPIO pin.")
parser.add_argument('process', type=str, help="The PID or process name to attach to.", default="openplc", nargs="?")
parser.add_argument('op', type=str, help="The operation to perform (read or write).", default="read", choices=['read', 'write', 'r', 'w'])
parser.add_argument('pin', type=str, help="The pin to read/write, in OpenPLC notation (%%QXx.y and %%IXx.y).")
parser.add_argument('value', type=bool, help="The value to be written to the chosen pin.", default=False, nargs="?")
args = parser.parse_args()

translation_table = {'%IX0.0': '0x8', '%IX0.1': '0x9', '%IX0.2': '0x7', '%IX0.3': '0x0', '%IX0.4': '0x2', '%IX0.5': '0x3', '%IX0.6': '0xc', '%IX0.7': '0xd', '%IX1.0': '0xe', '%IX1.1': '0x15', '%IX1.2': '0x16', '%IX1.3': '0x17', '%IX1.4': '0x18', '%IX1.5': '0x19', '%QX0.0': '0xf', '%QX0.1': '0x10', '%QX0.2': '0x4', '%QX0.3': '0x5', '%QX0.4': '0x6', '%QX0.5': '0xa', '%QX0.6': '0xb', '%QX0.7': '0x1a', '%QX1.0': '0x1b', '%QX1.1': '0x1c', '%QX1.2': '0x1d'}

write_op = ['w', 'write']
session = frida.attach(args.process)

script = session.create_script("""
        var translation_table = {8: '%IX0.0', 9: '%IX0.1', 7: '%IX0.2', 0: '%IX0.3', 2: '%IX0.4', 3: '%IX0.5', 12: '%IX0.6', 13: '%IX0.7', 14: '%IX1.0', 21: '%IX1.1', 22: '%IX1.2', 23: '%IX1.3', 24: '%IX1.4', 25: '%IX1.5', 15: '%QX0.0', 16: '%QX0.1', 4: '%QX0.2', 5: '%QX0.3', 6: '%QX0.4', 10: '%QX0.5', 11: '%QX0.6', 26: '%QX0.7', 27: '%QX1.0', 28: '%QX1.1', 29: '%QX1.2'}
        var digital_read_ptr = Module.getExportByName(null, 'digitalRead');
        var digital_write_ptr = Module.getExportByName(null, 'digitalWrite');

        var readPin = new NativeFunction(ptr(digital_read_ptr), 'int', ['int']);
        var writePin = new NativeFunction(ptr(digital_write_ptr), 'void', ['int', 'int']);

        rpc.exports.readPin = function(pin) {
            console.log("Value of pin " + translation_table[pin] + ": " + readPin(pin));
        };
        rpc.exports.writePin = function(pin, value) {
            writePin(pin, value);
        };
        """)
script.load()

actual_pin = int(translation_table[args.pin], 16)
if args.op in write_op:
    print(f"Writing {args.value} to pin {args.pin}")
    script.exports.write_pin(actual_pin, int(args.value))

script.exports.read_pin(actual_pin)

