from blake3 import blake3, KEY_LEN
import base64, json, string, random, traceback

def base64_encode(message):
    return base64.b64encode(message.encode('ascii'))

def base64_decode(message):
    return base64.b64decode(message).decode('ascii')

def random_32_string():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k = 32))

def create_token(payload, secret, header = json.dumps({"typ": "JWT","alg": "BLAKE3"})):
    header_encoded = base64_encode(header)
    payload_encoded = base64_encode(payload)
    signing = blake3(header_encoded + b"." + payload_encoded, key = secret.encode('ascii')).hexdigest()

    return f"{header_encoded.decode('ascii')}.{payload_encoded.decode('ascii')}.{signing}"

def verify_token(token, secret):
    try:
        [header, payload, signing] = token.split('.')

        generated_signing = blake3(
            header.encode('ascii') + b'.' + payload.encode('ascii'), 
            key = secret.encode('ascii')
        ).hexdigest()

        return signing == generated_signing
    except Exception as e:
        print("Error occured when verify token", e)
        traceback.print_exc()

def extract_header_payload(token):
    try:
        [header, payload, signing] = token.split('.')
        
        header = base64_decode(header)
        payload = base64_decode(payload)

        return [header, payload]
    except Exception as e:
        print("Error when extract token", e)
        traceback.print_exc()

if (__name__=="__main__"):
    header = {
        "typ": "JWT",
        "alg": "BLAKE3"
    }
    payload = {
        "user_id": "id1",
        "email": "user@gmail.com"
    }

    secret = '5J9YXGHNCDO6CI8SQJ8R1CFY3X00EWUV'
    true_token = create_token(json.dumps(payload), secret) 
    print("True token: ", true_token)
    assert verify_token(true_token, secret) == True, print("Verify token is failed!")

    false_token = 'akjdkasjdkasljdas.kldjaksdjaskldjaskldjaslkd.jakjdlaksjdaklsjdkasjdlaksjdl'
    assert verify_token(false_token, secret) != True, print("Verify token algorithm is not correct!")

    [ex_header, ex_payload] = extract_header_payload(true_token)
    assert json.loads(ex_header) == header
    assert json.loads(ex_payload) == payload