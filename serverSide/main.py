"""THIS MODULE IS DEPRECIATED"""

import RSA_keyGeneration
import ServerSide
import threading

def serverThread():
    """creates a thread that starts the server but allows the script to continue running"""
    t1 = threading.Thread(target=server.start_server)
    t1.start()
    return t1

def keyGeneration():
    key = RSA_keyGeneration.RSAKeyManager()
    key.save_keys()

def main():
    ...


if __name__ == "__main__":
    keyGeneration()
    server = ServerSide.SecureTCPServer()
    t1 = serverThread()
    print("IM STILL RUNNING")
    main()
    t1.join()
