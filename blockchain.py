import os
from collections import OrderedDict

import binascii

from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 100
WALLET_REWARD = 1000
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.students = []
        # for bootnode
        if os.path.exists('students.json'):
            f = open('students.json', 'r')
            self.students = json.loads(f.read())
        self.nodes = set()
        self.register_node("142.93.4.41:80")  # bootnode
        # Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        # Mine genesis block
        block = self.create_block(0, '00', [], MINING_SENDER)
        self.proof_of_work(block)
        self.chain.append(block)
        self.transactions = []

    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def verify_transaction_signature(self, sender_address, signature, transaction):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        public_key = RSA.importKey(binascii.unhexlify(sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))

    def submit_transaction(self, sender_address, recipient_address, value, signature):
        """
        Add a transaction to transactions array if the signature verified
        """
        transaction = OrderedDict({'sender_address': sender_address,
                                   'recipient_address': recipient_address,
                                   'value': value})
        print("Submitting transaction")
        # Reward for mining a block
        if sender_address == MINING_SENDER:
            print("This is a reward block")
            self.transactions.append(transaction)
            return len(self.chain) + 1
        # Manages transactions from wallet to another wallet
        else:
            print("This is a transaction block")
            transaction_verification = self.verify_transaction_signature(sender_address, signature, transaction)
            if transaction_verification:
                if not self.valid_chain(self.chain, {'sender_address': sender_address, 'value': value}):
                    print('invalid chain')
                    return False
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                print("invalid transaction verification!")
                return False

    def create_block(self, nonce, previous_hash, transactions, creator):
        """
        Add a block of transactions to the blockchain
        """
        block = {'block_number': len(self.chain) + 1,
                 'timestamp': time(),
                 'transactions': transactions,
                 'nonce': nonce,
                 'creator': creator,
                 'previous_hash': previous_hash}
        # Reset the current list of transactions
        return block

    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, block):
        """
        Proof of work algorithm
        """
        # last_block = self.chain[-1]
        # last_hash = self.hash(last_block)

        while self.valid_block(block) is False:
            block['nonce'] += 1

        return block['nonce']

    def valid_block(self, block, difficulty=MINING_DIFFICULTY):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """
        return self.hash(block)[:difficulty] == '0' * difficulty

    def valid_chain(self, chain, transaction_info=None):
        """
        check if a blockchain is valid
        """
        balance = 0
        created_wallets = set()
        for i in range(1, len(chain)):
            last_block = chain[i - 1]
            block = chain[i]
            if block['previous_hash'] != self.hash(last_block):
                return False
            if not self.valid_block(block):
                return False
            if transaction_info:
                sender_address = transaction_info['sender_address']
                rewards = set()
                for transaction in block['transactions']:
                    value = int(transaction['value'])
                    if transaction['sender_address'] == sender_address:
                        balance -= value
                    if transaction['recipient_address'] == sender_address:
                        if sender_address == MINING_SENDER:
                            if value is WALLET_REWARD and sender_address not in created_wallets:
                                balance += value
                            if value is MINING_REWARD and\
                                    sender_address == block['creator'] and\
                                    sender_address not in rewards:
                                balance += value
                                rewards.add(sender_address)

                        else:
                            balance += value
                    if transaction['sender_address'] == MINING_SENDER and value is MINING_REWARD:
                        created_wallets.add(transaction['sender_address'])

        return float(transaction_info['value']) < balance if transaction_info else True

    def resolve_conflicts(self):
        """
        Resolve conflicts between blockchain's nodes
        by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None
        nodes_to_add = set()
        new_students = None
        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network

        for node in neighbours:
            print('http://' + node + '/chain')
            response = requests.get('http://' + node + '/chain')
            if response.status_code == 200:
                response_json = response.json()
                length = response_json['length']
                chain = response_json['chain']
                nodes = response_json['nodes']
                students = response_json['students']
                nodes_to_add.update({node for node in nodes if node not in self.nodes})

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
                    new_students = students

        self.nodes.update(nodes_to_add)
        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            if new_students:
                self.students = new_students
            return True

        return False


# Instantiate the Node
app = Flask(__name__)
CORS(app)

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/')
def index():
    return render_template('node/index.html')


@app.route('/configure')
def configure():
    return render_template('node/configure.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    print('sender address: ' + values['sender_address'])
    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(values['sender_address'], values['recipient_address'],
                                                       values['amount'], values['signature'])

    if not transaction_result:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block ' + str(transaction_result)}
        return jsonify(response), 201


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.transactions

    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'nodes': list(blockchain.nodes),
        'students': blockchain.students
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...

    if len(blockchain.transactions) is 0:
        return jsonify({'message': 'No blocks to mine!'}), 408
    last_block = blockchain.chain[-1]

    # We must receive a reward for finding the proof.
    blockchain.submit_transaction(sender_address=MINING_SENDER, recipient_address=blockchain.node_id,
                                  value=MINING_REWARD, signature="")

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(0, previous_hash, blockchain.transactions, blockchain.node_id)
    blockchain.proof_of_work(block)
    blockchain.chain.append(block)
    blockchain.transactions = []
    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    given_name = request.args.get("name")
    given_id = request.args.get("id")
    hashed_id = hashlib.sha256(given_id.encode('UTF-8')).hexdigest()
    valid = False
    for student in blockchain.students:
        if student["id"] == hashed_id:
            if student["name"] == given_name:
                valid = not student["taken"]
                student["taken"] = True  # will always be true after this
            break
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii'),
        'valid': valid
    }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=80, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='142.93.4.41', port=port)
