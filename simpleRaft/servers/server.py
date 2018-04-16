import zmq
import threading
import pickle
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random


class Server(object):

    def __init__(self, name, state, log, messageBoard, neighbors):
        self._name = name
        self._state = state
        self._log = log
        self._messageBoard = messageBoard
        self._neighbors = neighbors
        self._total_nodes = 0

        self._commitIndex = 0
        self._currentTerm = 0

        self._lastApplied = 0

        self._lastLogIndex = 0
        self._lastLogTerm = None

        self._state.set_server(self)
        self._messageBoard.set_owner(self)

    def send_message(self, message):
        for n in self._neighbors:
            message._receiver = n._name
            n.post_message(message)

    def send_message_response(self, message):
        n = [n for n in self._neighbors if n._name == message.receiver]
        if(len(n) > 0):
            n[0].post_message(message)

    def post_message(self, message):
        self._messageBoard.post_message(message)

    def on_message(self, message):
        state, response = self._state.on_message(message)

        self._state = state

# private key is private key for server
# public keys maps _name to public key for that server


class ZeroMQServer(Server):
    def __init__(self, name, state, log, messageBoard, neighbors,
                 private_key,
                 public_keys,
                 port=6666):
        super(ZeroMQServer, self).__init__(name, state, log,
                                           messageBoard, neighbors)
        self._port = 6666
        self.public_keys = public_keys
        self.private_key = private_key

        class SubscribeThread(threading.Thread):
            def run(thread):
                context = zmq.Context()
                socket = context.socket(zmq.SUB)
                for n in neighbors:
                    socket.connect("tcp://%s:%d" % (n._name, n._port))

                while True:
                    message = socket.recv()
                    message_encrypted = message.data["encrypted"]
                    message_signature = message.data["signature"]

                    # Decrypt message data
                    message_str = self.private_key.decrypt(message_encrypted)

                    # Verify message
                    public_key = public_keys[message.sender]
                    message_hash = SHA256.new(message_str).digest()
                    if not public_key.verify(message_hash, message_signature):
                        continue

                    # Process recieved message
                    message.data = pickle.loads(message_str)
                    self.on_message(message)

        class PublishThread(threading.Thread):
            def run(thread):
                context = zmq.Context()
                socket = context.socket(zmq.PUB)
                socket.bind("tcp://*:%d" % self._port)

                while True:
                    message = self._messageBoard.get_message()
                    if not message:
                        continue

                    # Serialize message data
                    message_str = pickle.dumps(message.data)

                    # Sign message
                    message_hash = SHA256.new(message_str).digest()   
                    message_signature = self.private_key.sign(message_hash, '')

                    # Encryped message
                    public_key = public_keys[message.receiver]
                    enc_data = public_key.encrypt(message_str, 32)

                    # Send encrypted message
                    message.data = {"encrypted_message": encrypted_message,
                                    "signature": message_signature}
                    socket.send(message)

        self.subscribeThread = SubscribeThread()
        self.publishThread = PublishThread()

        self.subscribeThread.daemon = True
        self.subscribeThread.start()
        self.publishThread.daemon = True
        self.publishThread.start()
