import socket
import threading
import time
import KeyManager as km
import AccountManager as am

# Server socket and binding
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 1600))

# Creates account manager
accounts = am.AccountManager("accounts.txt")
accountDictionary = {}

def clientListener(con):
    """Listens to specific client, should be spawned under separate thread"""
    keys = km.KeyManager()

    # Sends public session key with certificate
    con.send(keys.getPublicKey() + b"|Certificate")
    resp = con.recv(1024)
    if resp == b"Close":
        con.close()
        return

    # Retrieves client session key, accepts connection
    clientSessionKey = keys.readPublicKey(resp)
    con.send(b"Accept")

    def sendToClient(plaintext, sessionKeys, clientKey, connection):
        """Internal function to send message with signature to client"""
        signature = sessionKeys.signUsingPrivateKey(plaintext)
        encryptedText = keys.encrypt(plaintext, clientKey)
        connection.send(encryptedText)
        time.sleep(0.1)
        connection.send(signature)

    # Keeps track of the current user
    currentUser = None

    # Loops infinitely while listening for messages and signatures
    while True:
        msg = con.recv(1024)
        # Closes if client requests to close connection
        if msg == b"Close":
            if currentUser is not None:
                accountDictionary[currentUser] = None
                currentUser = None
            con.close()
            return
        sig = con.recv(1024)

        # Verifies message using digital signature
        digest = keys.decryptUsingPrivateKey(msg)
        if keys.verifyUsingPublicKey(sig, digest, clientSessionKey):
            msgItems = digest.split(b"|")

            # Registers new user and sends response if registered
            if msgItems[0] == b"Register":
                res = accounts.addUser(msgItems[1], msgItems[2])
                if res:
                    sendToClient(b"Registered", keys, clientSessionKey, con)
                else:
                    sendToClient(b"Registration failed", keys, clientSessionKey, con)

            # Authenticates user and adds connection to dictionary for the user
            elif msgItems[0] == b"Login":
                if msgItems[1] not in accountDictionary and accounts.verifyUser(msgItems[1], msgItems[2]):
                    sendToClient(b"Authenticated", keys, clientSessionKey, con)

                    currentUser = msgItems[1]
                    accountDictionary[currentUser] = (con, clientSessionKey, keys)
                else:
                    sendToClient(b"Not authenticated", keys, clientSessionKey, con)

            # Receives current user's request to connect with another user
            elif msgItems[0] == b"PingUser":
                # Retrieves client's key info
                clientKeyInfo = con.recv(1024)

                # Checking basic conditions
                if currentUser is not None and msgItems[1] != currentUser and msgItems[1] in accountDictionary:
                    # Send request to second user, find connection in dictionary
                    con2 = accountDictionary[msgItems[1]][0]
                    clientSessionKey2 = accountDictionary[msgItems[1]][1]
                    sessionKeys2 = accountDictionary[msgItems[1]][2]
                    sendToClient(b"Request|" + currentUser, sessionKeys2, clientSessionKey2, con2)
                    time.sleep(0.1)
                    con2.send(clientKeyInfo)

                # Returning not found if basic conditions to connect are not met
                else:
                    sendToClient(b"Not found", keys, clientSessionKey, con)

            # Received connection request response from user
            elif msgItems[0] == b"RequestAccept" or msgItems[0] == b"RequestDecline":
                con2 = accountDictionary[msgItems[1]][0]
                clientSessionKey2 = accountDictionary[msgItems[1]][1]
                sessionKeys2 = accountDictionary[msgItems[1]][2]
                if msgItems[0] == b"RequestAccept":
                    clientKeyInfo = con.recv(1024)
                    sendToClient(b"RequestAccept", sessionKeys2, clientSessionKey2, con2)
                    time.sleep(0.1)
                    con2.send(clientKeyInfo)
                else:
                    sendToClient(b"RequestDecline", sessionKeys2, clientSessionKey2, con2)

            # User is sending message to friend
            elif msgItems[0] == b"SendingMessage":
                msgPacket = con.recv(1024)
                sigPacket = con.recv(1024)
                con2 = accountDictionary[msgItems[1]][0]
                con2.send(msgPacket)
                con2.send(sigPacket)

        # Received wrong signature, ignoring packet
        else:
            print("Received bad signature, dropping request")
            continue


# Listens infinitely for new connections
while True:
    print("Listening for connection requests...")
    s.listen(1)

    # Accept connection from client
    c, addr = s.accept()
    print("CONNECTION FROM:", str(addr))

    t = threading.Thread(target=clientListener, args=(c,))
    t.start()

c.close() 