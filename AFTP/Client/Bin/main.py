import socket
from .AFTPWarnings import DebugMessageWarning
from .errors import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from typing import Optional
import errno

class ClientAFTP:
    def __init__(self, conn: socket.socket, file: str, debug: Optional[bool] = False) -> None:
        self.__debug: bool = debug
        key = RSA.generate(2048)
        self.__public_key: RSA.RsaKey = key.publickey()
        self.__private_key: RSA.RsaKey = key
        self.__cipher: PKCS1_OAEP.PKCS1OAEP_Cipher = PKCS1_OAEP.new(self.__private_key)
        self.__conn: socket.socket = conn
        self.__file: str = file
        if type(self.__file) is not str:
            raise PreconditionError("File variable must be a string")
        self.Debug("[+] AFTP client started")
        self.__conn.sendall(self.__public_key.export_key())
        server_public_key_data = self.__conn.recv(4096)
        self.__ServerPublickey: RSA.RsaKey = RSA.import_key(server_public_key_data)
        self.__ServerCipher: PKCS1_OAEP.PKCS1OAEP_Cipher = PKCS1_OAEP.new(self.__ServerPublickey)
        self.Debug("[+] Server public key received and cipher generated")
    
    def IsConnectionOpen(self):
        try:
            err = self.__conn.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                return True
            else:
                return False
        except socket.error as e:
            if e.errno == errno.ENOTCONN:
                return False
            else:
                raise
    
    def Debug(self, *msg):
        try:
            if self.__debug:
                print("[+]", *msg)
        except Exception as e:
            print(DebugMessageWarning(f"{e}"))
    
    def SendFileContents(self) -> None:
        with open(self.__file, 'rb') as file:
            while True:
                data: bytes = file.read(128)
                try:
                    encrypted_data: bytes = self.__ServerCipher.encrypt(data)
                except Exception as e:
                    raise EncryptingError(f"Error while encrypting data to server\nError: {e}")
                try:
                    if not self.IsConnectionOpen():
                        raise ConnectionError(f"The connection is not open")
                    self.__conn.sendall(encrypted_data)
                except:
                    raise SendingError(f"Error while sending file {self.__file} to server\nError: {e}")
                self.__conn.sendall(encrypted_data)
                self.Debug("[+] Package sent to the server")
                self.__conn.recv(1024).decode()
    
    def Send(self) -> str:
        try:
            self.SendFileContents()
            return "File sent successfully"
        except Exception as e:
            raise SendingError(f"Error while sending file {self.__file} to server\nError: {e}")

    def DownloadFileContents(self):
        try:
            with open(self.__file, 'wb') as file:
                while True:
                    if not self.IsConnectionOpen():
                        raise ConnectionError(f"The connection is not open")
                    encrypted_data: bytes = self.__conn.recv(4096)
                    if not encrypted_data:
                        break
                    try:
                        data: bytes = self.__cipher.decrypt(encrypted_data)
                    except Exception as e:
                        raise DecryptingError(f"Error while encrypting data to server\nError: {e}")
                    file.write(data)
                    self.Debug("[+] Data written to file")
                    self.__conn.send("data written".encode())
        except Exception as e:
            raise RecivingError(f"Error while receiving file parts: {str(e)}")
    
    def Download(self):
        self.DownloadFileContents()
        return "File download complete"