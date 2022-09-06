# Secure TCP Client

This program is to demonstrate how a secure TCP connection occurs. This program utilize socket library from python and pycryptodome. Hence, before running the program, you will need to run `pip install pycryptodome`. To use this program, you will need two computers to show how two devices communicate using a secure TCP connection. There are several variables that you would like to modify based on your needs: `SELF_IP`, `SELF_PORT`, `PARTNER_IP`, `PARTNER_PORT`, and `BUFFER_SIZE`.

## How It Works
At the beginning of the run time, the program will generate both symmetric and assymetric keys. These keys will be used for securing your messages. Then, you will be given 5 options:
1. `Initator of Symmetric Messaging` - to act as symetricly encrypted message sender
2. `Receiver of Symmetric Messaging` - to act as symetricly encrypted message receiver
3. `Initiator of Assymetric Messaging` - to act as assymetricly encrypted message sender
4. `Receiver of Assymetric Messaging` - to act as assymetricly encrypted message receiver
5. `Terminate` - to terminate the program