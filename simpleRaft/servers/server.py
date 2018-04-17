import zmq
import threading
import pickle
from Crypto.Hash import SHA256


class Server(object):

    def __init__(self, name, state, log, messageBoard, neighbors,
                 crypto_enabled=False, public_keys=None, private_key=None):
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

        # crypto
        self.crypto_enabled = crypto_enabled
        self.public_keys = public_keys
        self.private_key = private_key

        self._state.set_server(self)
        self._messageBoard.set_owner(self)

    def send_message(self, message):
        if(self.crypto_enabled):
            # Sign message
            message_str = pickle.dumps(message.data)
            message._hash = SHA256.new(message_str).digest()  
            message._signature = self.private_key.sign(message.hash, '')

        for n in self._neighbors:
            message._receiver = n._name
            n.post_message(message)

    def send_message_response(self, message):
        if(self.crypto_enabled):
            # Sign message
            message_str = pickle.dumps(message.data)
            message._hash = SHA256.new(message_str).digest()  
            message._signature = self.private_key.sign(message.hash, '')

        n = [n for n in self._neighbors if n._name == message.receiver]
        if(len(n) > 0):
            n[0].post_message(message)

    def post_message(self, message):
        self._messageBoard.post_message(message)

    def on_message(self, message):

        if(self.crypto_enabled):
            # Verify message
            message_str = pickle.dumps(message.data)       
            message_hash = SHA256.new(message_str).digest()
            if not self.public_keys[message.sender].verify(message_hash, message.signature):
                return

        state, response = self._state.on_message(message)
        self._state = state

# private key is private key for server
# public keys maps _name to public key for that server


class ZeroMQServer(Server):
    def __init__(self, name, state, log, messageBoard, neighbors,
                 port=6666):
        super(ZeroMQServer, self).__init__(name, state, log,
                                           messageBoard, neighbors)
        self._port = 6666

        class SubscribeThread(threading.Thread):
            def run(thread):
                context = zmq.Context()
                socket = context.socket(zmq.SUB)
                for n in neighbors:
                    socket.connect("tcp://%s:%d" % (n._name, n._port))

                while True:
                    message = socket.recv()
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
                    socket.send(message)

        self.subscribeThread = SubscribeThread()
        self.publishThread = PublishThread()

        self.subscribeThread.daemon = True
        self.subscribeThread.start()
        self.publishThread.daemon = True
        self.publishThread.start()
