from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import socket
import secrets

SELF_IP = ""
SELF_PORT = 7740
PARTNER_IP = "34.67.240.226"
PARTNER_PORT = 6773
BUFFER_SIZE = 2048

def GenerateRSA():
    key_pair = RSA.generate(4096)
    public_key = key_pair.public_key()

    file = open("A_PublicKey.pem", "wb")
    file.write(public_key.export_key())

    file = open("A_PrivateKey.pem", "wb")
    file.write(key_pair.export_key())

def GenerateSymetricKey():
    symetric_key = secrets.token_hex(32)

    file = open("A_SymmetricKey.txt", "w")
    file.write(symetric_key)

def SymmetricInitiator():
    sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sc.connect((PARTNER_IP, PARTNER_PORT))

    message = "Halo Instance B!"
    message_encoded = message.encode("UTF-8")
    sc.send(message_encoded)

    # initiate message
    response_encoded = sc.recv(BUFFER_SIZE)
    response = response_encoded.decode("UTF-8")
    print(f"Message from instance B: {response}\n")

    # send key
    key_intialization = "Ini Symmetric Keynya"
    file = open("A_SymmetricKey.txt", "r")
    key_intialization += file.read()
    raw_key = key_intialization.encode("UTF-8")
    sc.send(raw_key)

    # create passkey
    key = bytes.fromhex(key_intialization[20:])
    cipher = AES.new(key, AES.MODE_ECB)

    # get response
    response = sc.recv(BUFFER_SIZE)
    print(f"Message before decryption: {response}")
    decrypted_response = unpad(cipher.decrypt(response), 32)
    readable_response = decrypted_response.decode("UTF-8")
    print(f"Message after decryption: {readable_response}")

    # message exchange
    while True:
        input_message = input('Enter your message: ')

        to_send_bytes = f"{input_message}"
        to_send_bytes = bytes(to_send_bytes, encoding="UTF-8")
        encrypt_input = cipher.encrypt(pad(to_send_bytes, 32))
        print(f"Message after encryption: {encrypt_input}")
        sc.send(encrypt_input)

        if (input_message.lower() == 'stop'):
            print ("You just terminate the connection")
            sc.close
            break

        print ("\nWaiting for partner to respond...\n")

        response_raw = sc.recv(BUFFER_SIZE)
        print(f"Message before decryption: {response_raw}")
        decrypted_response = unpad(cipher.decrypt(response_raw), 32)
        readable_response = decrypted_response.decode("UTF-8")
        print(f"Message after decryption: {readable_response}")

        if (readable_response.lower() == 'stop'):
            print ("Partner just terminate the connection")
            sc.close
            break

def SymmetricServer():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sc:
        sc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sc.bind((SELF_IP, SELF_PORT))
        sc.listen(0)
        connection, address = sc.accept()

        # receive initial message
        receive_raw = connection.recv(BUFFER_SIZE)
        receive = receive_raw.decode("UTF-8")
        print(f"{address} just initialized a connection with message: {receive}")

        return_message = "Halo Instance B!"
        encoded_message = return_message.encode("UTF-8")
        connection.send(encoded_message)

        # decode received key
        received_key_raw = connection.recv(BUFFER_SIZE)
        received_key = received_key_raw.decode("UTF-8")
        key = received_key[20:]
        print(received_key)

        symmetric_key = bytes.fromhex(key)
        cipher = AES.new(symmetric_key, AES.MODE_ECB)

        feedback_message = b"Symmetric Key diterima"
        encrypted_message = cipher.encrypt(pad(feedback_message, 32))
        connection.send(encrypted_message)

        while True:

            print ("\nWaiting for partner to respond...\n")

            received_message_raw = connection.recv(BUFFER_SIZE)
            print(f"Message before decryption: {received_message_raw}")
            decrypt_message = unpad(cipher.decrypt(received_message_raw), 32)
            decoded_message = decrypt_message.decode("UTF-8")
            print(f"Message after decryption: {decoded_message}\n")

            if (decoded_message.lower() == 'stop'):
                print ("Partner just terminate the connection")
                connection.close()
                break

            input_message = input('Enter your message: ')

            to_send_bytes = f"{input_message}"
            to_send_bytes = bytes(to_send_bytes, encoding="UTF-8")
            encrypt_input = cipher.encrypt(pad(to_send_bytes, 32))

            print(f"Message after encryption: {encrypt_input}")
            connection.send(encrypt_input)

            if (input_message.lower() == 'stop'):
                print ("You just terminate the connection")
                connection.close()
                break

def AssymetricInitiator():
    sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sc.connect((PARTNER_IP, PARTNER_PORT))

    initial_message = "Halo Instance B!"
    encoded_message = initial_message.encode("UTF-8")
    sc.send(encoded_message)

    response_raw = sc.recv(BUFFER_SIZE)
    response = response_raw.decode("UTF-8")
    print(f"Message from instance B: {response}")

    file = open("A_SymmetricKey.txt","r")
    key = file.read()

    # send pub key
    file = open("A_PublicKey.pem","rb")
    public_key = file.read()
    sc.send(public_key)

    # received partner's pub key
    partner_key_raw = sc.recv(BUFFER_SIZE)
    partner_key = RSA.import_key(partner_key_raw)
    cipher_partner =  PKCS1_OAEP.new(partner_key)
    print(f"Partner just sent a public key: {partner_key_raw}")

    # encrypt symmetric key using partner's pub key
    hex_key = bytes.fromhex(key)
    encrypted_key = cipher_partner.encrypt(hex_key)
    sc.send(encrypted_key)

    cipher = AES.new(hex_key, AES.MODE_ECB)

    # get response
    response_raw = sc.recv(BUFFER_SIZE)
    print(f"Message before decryption: {response_raw}")
    decrypted_response = unpad(cipher.decrypt(response_raw), 32)
    decoded_response = decrypted_response.decode("UTF-8")
    print(f"Message after decrypted: {decoded_response}")

    # message exchange
    while True:
        input_message = input('Enter your message: ')

        to_send_bytes = f"{input_message}"
        to_send_bytes = bytes(to_send_bytes, encoding="UTF-8")
        encrypt_input = cipher.encrypt(pad(to_send_bytes, 32))
        print(f"Message after encryption: {encrypt_input}")
        sc.send(encrypt_input)

        if (input_message.lower() == 'stop'):
            print ("You just terminate the connection")
            sc.close
            break

        print ("\nWaiting for partner to respond...\n")

        response_raw = sc.recv(BUFFER_SIZE)
        print(f"Message before decryption: {response_raw}")
        decrypted_response = unpad(cipher.decrypt(response_raw), 32)
        readable_response = decrypted_response.decode("UTF-8")
        print(f"Message after decryption: {readable_response}")

        if (readable_response.lower() == 'stop'):
            print ("Partner just terminate the connection")
            sc.close
            break

def AssymetricServer():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sc:
        sc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sc.bind((SELF_IP, SELF_PORT))
        sc.listen(0)

        connection, address = sc.accept()

        raw_message = connection.recv(BUFFER_SIZE)
        message = raw_message.decode("UTF-8")
        print(f"{address} just initialized a connection with message: {message}")

        raw_response = "Halo Instance B!"
        encoded_response = raw_response.encode("UTF-8")
        connection.send(encoded_response)

        # retrieve pub key from partner
        raw_partner_key = connection.recv(BUFFER_SIZE)
        partner_key = raw_partner_key.decode("UTF-8")
        print(f"{address} just sent a public key: {partner_key}")

        # send public key to partner
        file = open("A_PublicKey.pem", "rb")
        pub_key = file.read()
        connection.send(pub_key)

        # prepare private key
        file = open("A_PrivateKey.pem", "rb")
        private_key_raw = file.read()
        import_private_key = RSA.import_key(private_key_raw)
        cipher_private_key = PKCS1_OAEP.new(import_private_key)

        # retrieve symmetric key
        sym_key_raw = connection.recv(BUFFER_SIZE)
        decrypted_sym_key = cipher_private_key.decrypt(sym_key_raw)
        hex_decryption = decrypted_sym_key.hex()
        print(f"Symmetric Key: {hex_decryption}")

        # keypass
        symmetric_key = bytes.fromhex(hex_decryption)
        cipher = AES.new(symmetric_key, AES.MODE_ECB)

        # encrypt message
        raw_confirmation = b"Symmetric Key diterima"
        encrypted_confirmation = cipher.encrypt(pad(raw_confirmation, 32))
        connection.send(encrypted_confirmation)

        while True:
            received_message_raw = connection.recv(BUFFER_SIZE)
            print(f"Message before decryption: {received_message_raw}")
            decrypt_message = unpad(cipher.decrypt(received_message_raw), 32)
            decoded_message = decrypt_message.decode("UTF-8")
            print(f"Message after decryption: {decoded_message}")

            if (decoded_message.lower() == 'stop'):
                print ("Partner just terminate the connection")
                connection.close()
                break

            input_message = input('Enter your message: ')

            to_send_bytes = f"{input_message}"
            to_send_bytes = bytes(to_send_bytes, encoding="UTF-8")
            encrypt_input = cipher.encrypt(pad(to_send_bytes, 32))

            print(f"Message after encryption: {encrypt_input}")
            connection.send(encrypt_input)

            if (input_message.lower() == 'stop'):
                print ("You just terminate the connection")
                connection.close()
                break



print("Generating Symmetric Key....")
GenerateSymetricKey()
print()
print("Generating Assymetric Key...")
GenerateRSA()

while True:
    request_message = '''
    Welcome! Tell me what do you want to do\n
    1. Initator of Symmetric Messaging\n
    2. Receiver of Symmetric Messaging\n
    3. Initiator of Assymetric Messaging\n
    4. Receiver of Assymetric Messaging\n
    5. Terminate\n\n
    '''
    request = input(request_message)

    if (request == '1'):
        print ("\nYou are a client\n")
        SymmetricInitiator()

    elif (request == '2'):
        print ("\nYou are a server\n")
        SymmetricServer()

    elif (request == '3'):
        print ("\nYou are a client\n")
        AssymetricInitiator()

    elif (request == '4'):
        print ("\nYou are a server\n")
        AssymetricServer()

    elif (request == '5'):
        print ("Thank you for letting  me rest :D, goodbye!\n")
        break
    else:
        print("Invalid input! Please enter the number of available options\n")