
# Command and Control

This program allows a user to issue commands via  a GUI to a client application.

## Installation

The modules tkinter, pwd and netifaces are required to run this program. 
Tkinter and pwd should be preinstalled in Pythons built-in modules on Linux.

Note: The pwd module is Linux only.

https://pypi.org/project/netifaces/

https://docs.python.org/3/library/tkinter.html

https://docs.python.org/3/library/pwd.html


## Tkinter Installation

### Windows:
    pip install tk

### Linux:
    (Debian) sudo apt install python-tk
    (Arch) sudo pacman -S tk

## Netifaces Installation

## Windows:
    pip install netifaces

## Linux:
    pip3 install netifaces



## Client Usage
Connect to the default controller address localhost:1234:

    python3 client.py

Connect to custom controller address:

    python3 client.py -a 192.168.1.27 -p 8080


## Controller Usage


