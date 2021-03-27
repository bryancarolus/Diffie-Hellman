# Client
import socket
import random
import hashlib

# Initialise socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Choosing a random number
b = random.randint(2, 100)

# Send a connection request to server
message = "Hello Server"
client_socket.sendto(message.encode("utf-8"), ("127.0.0.1", 1234))

# Receives Diffie-Hellman Parameters from Server
data, addr = client_socket.recvfrom(1024)
print("Receive Diffie-Hellman Parameters")
dh_parameters = data.decode("utf-8").split("||")
p = dh_parameters[0]
g = dh_parameters[1]
print("p = " + p)
print("g = " + g)

# Compute g^b mod p
print("Computes g^b mod p")
gb_p = pow(int(g), b, int(p))

# Sends g^b mod p to Server
print("Sends g^b mod p to Server")
data1 = str(gb_p).encode("utf-8")
client_socket.sendto(data1, ("127.0.0.1", 1234))

# Receives g^a mod p from Server
print("Receives g^a mod p from Server")
data2, addr = client_socket.recvfrom(1024)
ga_p = int(data2.decode("utf-8"))

# Compute DH Key (g^ab mod p)
print("Compute Key")
key = pow(ga_p, b, int(p))
print()


# Using the key to communicate by generating Message Authentication Code (MAC)
def authenticate_message(received_msg, mac, DHkey):
    get_hmac = hashlib.sha256((str(DHkey) + received_msg + str(DHkey)).encode("utf-8")).hexdigest()
    if get_hmac == mac:
        return True
    else:
        return False


print("Enter \"Q\" to terminate the connection")
while True:
    # Sending Message
    user_input = input("Client: ")
    hmac = hashlib.sha256((str(key) + user_input + str(key)).encode("utf-8")).hexdigest()
    msg = user_input + "||" + hmac
    client_socket.sendto(msg.encode("utf-8"), ("127.0.0.1", 1234))

    if user_input == "Q":
        break

    # Receiving Message
    server_msg, addr = client_socket.recvfrom(1024)
    reply_arr = server_msg.decode("utf-8").split("||")

    verified = authenticate_message(reply_arr[0], reply_arr[1], key)

    if verified:
        print("Server: " + reply_arr[0])

        if reply_arr[0] == "Q":
            break
    else:
        print("Message Authentication Failed")

client_socket.close()
