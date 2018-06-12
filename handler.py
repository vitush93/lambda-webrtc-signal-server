import boto3
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

sqs = boto3.client('sqs')

event_example = {
    "pkey": "<pkcs1 public key>",
    "sig": "<base64 encoded signature>",
    "payload": "<JSON encoded string\
             {\
                \"type\": \"offer|answer|ice\",\
                \"for\": < pkcs1 public key > , \
                \"message\": <message to deliver: sdp or ice candidate>\
             }>"
}


def handle(event, context):
    # validate event
    payload = {}
    type = ''
    for_key = ''
    pkey = ''
    if 'pkey' not in event or 'sig' not in event or 'payload' not in event:
        return 'required fields: pkey, sig, payload'
    else:
        try:
            pkey = RSA.importKey(event['pkey'])

            verified = verify_signature(pkey, event['sig'], event['payload'])
            if not verified:
                return 'signature verification failed'
        except (ValueError, TypeError, IndexError):
            return 'pkey: not a valid pkcs1 public key'

        try:
            payload = json.loads(event['payload'])

            if 'type' not in payload:
                return 'payload: type field required'
            type = payload['type']

            if type != 'offer' and type != 'answer' and type != 'ice':
                return 'valid payload types: offer, answer, ice'

            if 'for' not in payload:
                return 'payload: for field required (public key)'
            try:
                for_key = RSA.importKey(payload['for'])
            except (ValueError, TypeError, IndexError):
                return 'for: not a valid pkcs1 public key'

            if 'message' not in payload:
                return 'payload: message field required'
        except ValueError:
            return 'payload: not a valid JSON encoded string'

    queue_name = derive_queue_name(pkey, for_key)
    create_queue_response = sqs.create_queue(
        QueueName=queue_name,
        Attributes={
            'VisibilityTimeout': '0'
        }
    )
    queue_url = create_queue_response['QueueUrl']

    # retrieve current top message (if any)
    receive_message_response = sqs.receive_message(QueueUrl=queue_url)
    if 'Messages' in receive_message_response:
        prev_message = receive_message_response['Messages'][0]
    else:
        prev_message = {}

    # send message to the queue
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=payload['message']
    )

    # delete previous message
    if prev_message != {}:
        sqs.delete_message(
            QueueUrl=queue_url,
            ReceiptHandle=prev_message['ReceiptHandle']
        )

        return prev_message['Body']
    else:
        return ''


def verify_signature(key, base64_signature, string_data):
    signer = PKCS1_v1_5.new(key)
    digest = SHA256.new()

    digest.update(string_data.encode('utf-8'))
    print(digest.hexdigest())
    if signer.verify(digest, base64.b64decode(base64_signature)):
        return True
    return False


def derive_queue_name(pkey1, pkey2):
    # TODO

    return 'test-queue'
