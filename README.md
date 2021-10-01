# rpi-openplc-gpio-tools
Tools to inspect the GPIO pin values, focused on being used to inspect the binary that [OpenPLC](https://www.openplcproject.com) runs.
# Requirements
The only requirement is the frida python API, installable with pip: ` pip3 install frida `.
Currently the only tested python version is 3.7.3, but the scripts should work on any python version that the frida python API supports.
# Why not just use the wiringPi library directly?
Well that is no fun! More seriously tho, this instrumentation was made to be able to poke around the state the PLC program that OpenPLC is running.
This means that there might be other parts of the state than just the values on the GPIO pins that is interesting later on, and then we already have the instrumentation ready.
# Tools
Currently, there are two scripts in this repository.
## openplc-read-all-pins.py
```
usage: openplc-read-all-pins.py [-h] [process]

Continuously output the values of the GPIO pins.

positional arguments:
  process     The PID or process name to attach to.

optional arguments:
  -h, --help  show this help message and exit
  ```
This script hooks either a process given on the command line (the name it expects is the name that can be found in the comm file in proc, for example /proc/1/comm) or if no process name given, defaults to the name ` openplc `.
It then setups hooks on the digitalRead and digitalWrite functions and copies the values of the Input and Output pins set by these functions, in the inputs and outputs dictionary and each second, outputs these dictionaries.
## openplc-read-set-pin.py
```
usage: openplc-read-set-pin.py [-h] [process] {read,write,r,w} pin [value]

Get or set a GPIO pin.

positional arguments:
  process           The PID or process name to attach to.
  {read,write,r,w}  The operation to perform (read or write).
  pin               The pin to read/write, in OpenPLC notation (%QXx.y and
                    %IXx.y).
  value             The value to be written to the chosen pin.

optional arguments:
  -h, --help        show this help message and exit
```
This script also hooks either a process given on the command line, or defaults to ` openplc `.
It then either reads or writes the GPIO pin given, which has to be with the name that OpenPLC refers to the pins with see this [link](https://www.openplcproject.com/runtime/raspberry-pi/pinout.png) for reference.
The default value written, if ` --op write `, is false (aka 0).
Any value given is going to be coerced into a bool, which usually means that any value given means true and to write false, you'll have to omit the value.
