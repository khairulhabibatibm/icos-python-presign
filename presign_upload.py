# Source from https://cloud.ibm.com/docs/cloud-object-storage?topic=cloud-object-storage-presign-url

import hashlib
import hmac
from requests.utils import quote



# hashing methods
def hash(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


# region is a wildcard value that takes the place of the AWS region value
# as COS doen't use regions like AWS, this parameter can accept any string
def createSignatureKey(key, datestamp, region, service):
    keyDate = hash(('AWS4' + key).encode('utf-8'), datestamp)
    keyRegion = hash(keyDate, region)
    keyService = hash(keyRegion, service)
    keySigning = hash(keyService, 'aws4_request')
    return keySigning



def hex_hash(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).hexdigest()
def createHexSignatureKey(key, datestamp, region, service):
    keyDate = hex_hash(('AWS4' + key).encode('utf-8'), datestamp)
    keyRegion = hex_hash(keyDate.encode('utf-8'), region)
    keyService = hex_hash(keyRegion.encode('utf-8'), service)
    keySigning = hex_hash(keyService.encode('utf-8'), 'aws4_request')
    return keySigning