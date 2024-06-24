import hashlib
import json
import time
from jwcrypto.common import base64url_encode
from jwcrypto import jwk, jws

class DIDSelfRegistry:
    def __init__(self, owner_jwk:'jws.JWK'):
        self._did = ""
        self._document_proof = ""
        self._did_document = {}
        self._owner_jwk = owner_jwk

             
    def _generate_document_proof(self, did_document:list, lifetime:int):
        document_sha256 = hashlib.sha256()
        document_sha256.update(json.dumps(did_document).encode('utf-8'))
        key_dict = self._owner_jwk.export_public(as_dict=True)
        alg = ""
        iat = int(time.time())
        if key_dict['kty'] == 'OKP':
            alg = 'EdDSA'
        elif key_dict['kty'] == 'EC' and key_dict['crv'] == 'P-256':
            alg = 'ES256'
        jws_payload_dict = {
            'iat': iat,
            'exp': iat + lifetime,
            's256': base64url_encode(document_sha256.digest())
        }
        jws_header_dict = {
            'alg': alg,
            'jwk': key_dict
        }
        jws_payload = json.dumps(jws_payload_dict)
        jws_header = json.dumps(jws_header_dict)
        proof = jws.JWS(jws_payload.encode('utf-8'))
        proof.add_signature(self._owner_jwk, None, jws_header,None)
        return proof
    
    def _verify_proof(self, did, did_document, document_proof):
        #--------------Verify sha-256 in proof----------
        document_sha256 = hashlib.sha256()
        document_sha256.update(json.dumps(did_document).encode('utf-8'))
        document_sha256_b64 = base64url_encode(document_sha256.digest())
        document_proof_jws = jws.JWS()
        document_proof_jws.deserialize(document_proof)
        payload = json.loads(document_proof_jws.objects['payload'].decode())
        header = json.loads(document_proof_jws.objects['protected'])
        if(document_sha256_b64 != payload['s256']):
            raise Exception("The sha-256 included in the proof is not valid")
            return -1
        #--------------Verify that the JKW in the header is correct-----
        _jwk = jwk.JWK.from_json(json.dumps(header['jwk'])) #<--Surround it try except
        _did = "did:self:" + _jwk.thumbprint()
        if ( _did != did):
            raise Exception("The proof header contains invalid key")
            return -1
        #--------------Verify time-----------------
        current_time = int(time.time())
        if  current_time < payload['iat'] or current_time > payload['exp']:
            raise Exception("The DID document has either expired or it has been issued at a future time")
            return -1
        #--------------Verify proofs---------------
        claimed_proof = jws.JWS()
        claimed_proof.deserialize(document_proof)
        claimed_proof.verify(_jwk)
        return True

    def _verify_document(self, did_document:list):
        if ("id" not in did_document):
            raise Exception("The DID document does not contain id")

    def create(self, did_document:list, lifetime:int=1200):
        if (not self._owner_jwk):
            raise Exception("Registry has to be configured with a JWK for this operation") 
        proof = self._generate_document_proof(did_document, lifetime)
        self.load(did_document, proof.serialize(compact=True))
    
    def read(self):
        return self._did_document, self._document_proof
    
    def update(self, did_document:list, lifetime:int=1200):
        if (not self._owner_jwk):
            raise Exception("Registry has to be configured with a JWK for this operation")
        if (did_document["id"] != self._did):
             raise Exception("The DID document does not contain a valid id")
        proof = self._generate_document_proof(did_document, lifetime)
        self.load(did_document, proof.serialize(compact=True))


    def load(self, did_document:list, document_proof:str): 
        self._verify_document(did_document)     
        try:
            self._verify_proof(did_document['id'], did_document, document_proof)             
        except:
            raise Exception("Invalid proof")
            return -1
        self._did_document = did_document
        self._document_proof = document_proof
        self._did = did_document['id']

    def exportX509(self, public_key, format="PEM"):
        from datetime import datetime, timezone, timedelta
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives import hashes, serialization
        import base64 
        subject = issuer = x509.Name([
            
        ])
        root = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            load_pem_public_key(self._owner_jwk.export_to_pem(private_key=False, password=None))
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.now(timezone.utc) + timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(self._did)]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(load_pem_private_key(self._owner_jwk.export_to_pem(private_key=True, password=None), password=None), hashes.SHA256())

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            load_pem_public_key(public_key)
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.now(timezone.utc) + timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(self._did)]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(load_pem_private_key(self._owner_jwk.export_to_pem(private_key=True, password=None), password=None), hashes.SHA256())
        if (format=="DER"):
            return [
                base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),
                base64.b64encode(root.public_bytes(serialization.Encoding.DER)).decode()
                ]
        if (format=="PEM"):
             return [root.public_bytes(serialization.Encoding.PEM), cert.public_bytes(serialization.Encoding.PEM)]
    
 

    



   
        


