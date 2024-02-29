import socket
from .errors import PreconditionError, SendingError, RecivingError
from threading import Thread
from typing import Optional
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import ssl

class ServerAFTP:
    def __init__(self, conn: socket.socket, addr: tuple, file: str, debug: Optional[bool] = False) -> None:
        self.__addr: tuple = addr
        self.__debug: bool = debug
        self.Debug("AFTP client started")
        key = RSA.generate(2048)
        self.__public_key: RSA.RsaKey = key.publickey()
        self.__private_key: RSA.RsaKey = key
        self.__cipher: PKCS1_OAEP.PKCS1OAEP_Cipher = PKCS1_OAEP.new(self.__private_key)
        self.__conn: socket.socket = conn
        self.__file: str = file
        if type(self.__file) is not str:
            raise PreconditionError("file variable must be a string")
        if type(self.__addr) is not tuple:
            raise PreconditionError("addr variable must be a tuple")
        self.__conn.sendall(self.__public_key.export_key())
        Ckey = self.__conn.recv(4096)
        self.__ClientPublickey: RSA.RsaKey = RSA.import_key(Ckey)
        self.__ClientCipher: PKCS1_OAEP.PKCS1OAEP_Cipher = PKCS1_OAEP.new(self.__ClientPublickey)
        self.Debug("Server public key received and cipher generated")
    
    def Debug(self, *msg):
        if self.__debug:
            print("[+]", *msg)
    
    def SendFileContents(self) -> None:
        with open(self.__file, 'rb') as file:
            while True:
                data: bytes = file.read(128)
                if not data:
                    break
                encrypted_data = self.__ClientCipher.encrypt(data)
                print(encrypted_data)
                self.__conn.sendall(encrypted_data)
                self.Debug(f"Package sent to {self.__addr}")
                print(self.__conn.recv(1024).decode())
    
    def Send(self) -> str:
        try:
            self.SendFileContents()
            return "File sent successfully"
        except Exception as e:
            raise SendingError(f"Error while sending file {self.__file} to {self.__addr}\nError: {e}")

    def DownloadFileContents(self):
        try:
            with open(self.__file, 'wb') as file:
                while True:
                    encrypted_data = self.__conn.recv(4096)
                    if not encrypted_data:
                        break
                    data = self.__cipher.decrypt(encrypted_data)
                    file.write(data)
                    self.Debug("[+] Data written to file")
                    self.__conn.send("data written".encode())
        except Exception as e:
            raise RecivingError(f"Error while receiving file parts: {str(e)}")
    
    def Download(self):
        self.DownloadFileContents()
        return "File download complete"
