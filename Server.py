# Server
import socket
import random
import hashlib

# Initialise socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("127.0.0.1", 1234))

# Diffie-Hellman Parameters
p = 8087
g = 23

# Choosing random number
a = random.randint(2, 100)

# Receives request from Client
data, addr = server_socket.recvfrom(1024)
print("Client requesting a connection")

# Sending Diffie-Hellman Parameters to Client
print("Sending Diffie-Hellman parameters")
message = str(p) + "||" + str(g)
server_socket.sendto(message.encode("utf-8"), addr)

# Compute g^a mod p
print("Computes g^a mod p")
ga_p = pow(g, a, p)

# Receives g^b mod p from Client
print("Receives g^b mod p from Client")
data1, addr = server_socket.recvfrom(1024)
gb_p = int(data1.decode("utf-8"))

# Sends g^a mod p to Client
print("Sends g^a mod p to Client")
data2 = str(ga_p).encode("utf-8")
server_socket.sendto(data2, addr)

# Compute DH Key (g^ab mod p)
print("Compute Key")
key = pow(gb_p, a, p)
print()


# Using the key to communicate by producing Message Authentication Code (MAC)
def authenticate_message(received_msg, mac, DHkey):
    get_hmac = hashlib.sha256((str(DHkey) + received_msg + str(DHkey)).encode("utf-8")).hexdigest()
    if get_hmac == mac:
        return True
    else:
        return False


print("Enter \"Q\" to terminate the connection")
while True:
    # Receiving Message
    client_msg, addr = server_socket.recvfrom(1024)
    msg_arr = client_msg.decode("utf-8").split("||")

    verified = authenticate_message(msg_arr[0], msg_arr[1], key)

    if verified:
        print("Client: " + msg_arr[0])

        if msg_arr[0] == "Q":
            break
    else:
        print("Message Authentication Failed")

    # Sending Message
    user_input = input("Server: ")
    hmac = hashlib.sha256((str(key) + user_input + str(key)).encode("utf-8")).hexdigest()
    msg = user_input + "||" + hmac
    server_socket.sendto(msg.encode("utf-8"), addr)

    if user_input == "Q":
        break

server_socket.close()
