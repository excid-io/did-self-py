from didself import registry
from jwcrypto import jwk, jws
import json

# DID creation
# Generate DID and initial secret key
did_key = jwk.JWK.generate(kty='EC', crv='P-256')
# Initialize registry
owner_registry = registry.DIDSelfRegistry(did_key)

# Generate the DID document
did_key_dict = did_key.export_public(as_dict=True)
did = "did:self:" + did_key.thumbprint()
did_document = {
    'id': did,
    'authentication': [{
        'id': '#key1',
        'type': "JsonWebKey2020",
        'publicKeyJwk': did_key_dict
    }],  
}

owner_registry.create(did_document)
#-------------Dumping-------------------
document, proof = owner_registry.read()
print("DID document:")
print(json.dumps(document, indent=2))
print("DID document proof:")
print(proof)
document_proof = jws.JWS()
document_proof.deserialize(proof)
payload = json.loads(document_proof.objects['payload'].decode())
print("Document proof payload:")
print(json.dumps(payload, indent=2))
print("Document proof signature:")
print(document_proof.objects['signature'].hex())
print("----------------------------------")

# Change the authentication key
authentication_jwk = jwk.JWK.generate(kty='OKP', crv='Ed25519')
did_document = {
    'id': did,
    'authentication': [{
        'id': '#key2',
        'type': "JsonWebKey2020",
        'publicKeyJwk': authentication_jwk.export_public(as_dict=True)
    }]
}

owner_registry.update(did_document)
#-------------Dumping-------------------
document, proof = owner_registry.read()
print("DID document:")
print(json.dumps(document, indent=2))
print("DID document proof:")
print(proof)
document_proof = jws.JWS()
document_proof.deserialize(proof)
payload = json.loads(document_proof.objects['payload'].decode())
print("Document proof payload:")
print(json.dumps(payload, indent=2))
print("Document proof signature:")
print(document_proof.objects['signature'].hex())
print("----------------------------------")


