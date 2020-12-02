from presign_upload import createSignatureKey
from presign_upload import createHexSignatureKey
from presign_upload import hex_hash
import datetime
import hashlib
import hmac
import requests
from requests.utils import quote

def main(params):
    object_key = params['object_key']
    bucket = params['bucket']
    access_key = params['access_key']
    secret_key = params['secret_key']
    region = params['region']

    switcher = {
        'jp-tok':'s3.jp-tok.cloud-object-storage.appdomain.cloud',
        'au-syd':'s3.au-syd.cloud-object-storage.appdomain.cloud',
        'eu-de':'s3.eu-de.cloud-object-storage.appdomain.cloud',
        'eu-gb':'s3.eu-gb.cloud-object-storage.appdomain.cloud',
        'jp-osa':'s3.jp-osa.cloud-object-storage.appdomain.cloud',
        'us-east':'s3.us-east.cloud-object-storage.appdomain.cloud',
        'us-south':'s3.us-south.cloud-object-storage.appdomain.cloud',
    }
    cos_endpoint = switcher.get(region,'s3.us-south.cloud-object-storage.appdomain.cloud')
    host = cos_endpoint
    endpoint = 'https://' + host

    # hardcoded for fix param
    expiration = 3600  # time in seconds
    http_method = 'PUT'

    # assemble the standardized request
    time = datetime.datetime.utcnow()
    timestamp = time.strftime('%Y%m%dT%H%M%SZ')
    datestamp = time.strftime('%Y%m%d')

    standardized_querystring = ('X-Amz-Algorithm=AWS4-HMAC-SHA256' +
                                '&X-Amz-Credential=' + access_key + '/' + datestamp + '/' + region + '/s3/aws4_request' +
                                '&X-Amz-Date=' + timestamp +
                                '&X-Amz-Expires=' + str(expiration) +
                                '&X-Amz-SignedHeaders=host')
    standardized_querystring_url_encoded = quote(standardized_querystring, safe='&=')

    standardized_resource = '/' + bucket + '/' + object_key
    standardized_resource_url_encoded = quote(standardized_resource, safe='&')

    payload_hash = 'UNSIGNED-PAYLOAD'
    standardized_headers = 'host:' + host + '\n'
    signed_headers = 'host'

    standardized_request = (http_method + '\n' +
                            standardized_resource + '\n' +
                            standardized_querystring_url_encoded + '\n' +
                            standardized_headers + '\n' +
                            signed_headers + '\n' +
                            payload_hash)

    # assemble string-to-sign
    hashing_algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + 's3' + '/' + 'aws4_request'
    sts = (hashing_algorithm + '\n' +
        timestamp + '\n' +
        credential_scope + '\n' +
        hashlib.sha256(standardized_request.encode('utf-8')).hexdigest())

    # generate the signature
    signature_key = createSignatureKey(secret_key, datestamp, region, 's3')
    signature = hmac.new(signature_key,
                        (sts).encode('utf-8'),
                        hashlib.sha256).hexdigest()

    # create and send the request
    # the 'requests' package autmatically adds the required 'host' header
    request_url = (endpoint + '/' +
                bucket + '/' +
                object_key + '?' +
                standardized_querystring_url_encoded +
                '&X-Amz-Signature=' +
                signature)

    print('request_url: %s' % request_url)

    print ('\nSending `%s` request to IBM COS -----------------------' % http_method)
    print ('Request URL = ' + request_url)
    request = requests.put(request_url)

    print ('\nResponse from IBM COS ---------------------------------')
    print ('Response code: %d\n' % request.status_code)
    print (request.text)


    # this information can be helpful in troubleshooting, or to better
    # understand what goes into signature creation
    print ('These are the values used to construct this request.')
    print ('Request details -----------------------------------------')
    print ('http_method: %s' % http_method)
    print ('host: %s' % host)
    print ('region: %s' % region)
    print ('endpoint: %s' % endpoint)
    print ('bucket: %s' % bucket)
    print ('object_key: %s' % object_key)
    print ('timestamp: %s' % timestamp)
    print ('datestamp: %s' % datestamp)

    print ('Standardized request details ----------------------------')
    print ('standardized_resource: %s' % standardized_resource_url_encoded)
    print ('standardized_querystring: %s' % standardized_querystring_url_encoded)
    print ('standardized_headers: %s' % standardized_headers)
    print ('signed_headers: %s' % signed_headers)
    print ('payload_hash: %s' % payload_hash)
    print ('standardized_request: %s' % standardized_request)

    print ('String-to-sign details ----------------------------------')
    print ('credential_scope: %s' % credential_scope)
    print ('string-to-sign: %s' % sts)
    print ('signature_key: %s' % signature_key)
    print ('signature: %s' % signature)

    print ('Because the signature key has non-ASCII characters, it is')
    print ('necessary to create a hexadecimal digest for the purposes')
    print ('of checking against this example.')

    region_bytes = region.encode()
    signature_key_hex = createHexSignatureKey(secret_key, datestamp, region, 's3')

    print ('signature_key (hexidecimal): %s' % signature_key_hex)

    print ('Header details ------------------------------------------')
    print ('pre-signed url: %s' % request_url)

    return {"presign_url": request_url}
    