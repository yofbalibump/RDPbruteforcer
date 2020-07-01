import socket
import ssl
import time
from struct import pack, unpack
from binascii import unhexlify, hexlify
from impacket.spnego import *
from impacket.examples import logger
from impacket import ntlm, version
from impacket.ntlm import *
from impacket.structure import Structure
from impacket.spnego import GSSAPI, ASN1_SEQUENCE, ASN1_OCTET_STRING, asn1decode, asn1encode
from impacket.dcerpc.v5 import nrpc
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import ERROR_MESSAGES
from impacket.nt_errors import STATUS_LOGON_FAILURE,                                 STATUS_SUCCESS,                 STATUS_ACCESS_DENIED, STATUS_NOT_SUPPORTED, \
     STATUS_MORE_PROCESSING_REQUIRED


TDPU_CONNECTION_REQUEST  = 0xe0
TPDU_CONNECTION_CONFIRM  = 0xd0
TDPU_DATA                = 0xf0
TPDU_REJECT              = 0x50
TPDU_DATA_ACK            = 0x60

# RDP_NEG_REQ constants
TYPE_RDP_NEG_REQ = 1
PROTOCOL_RDP     = 0
PROTOCOL_SSL     = 1
PROTOCOL_HYBRID  = 2
PROTOCOL_HYBRID_EX = 8

# RDP_NEG_RSP constants
TYPE_RDP_NEG_RSP = 2
EXTENDED_CLIENT_DATA_SUPPORTED = 1
DYNVC_GFX_PROTOCOL_SUPPORTED   = 2

# RDP_NEG_FAILURE constants
TYPE_RDP_NEG_FAILURE                  = 3
SSL_REQUIRED_BY_SERVER                = 1
SSL_NOT_ALLOWED_BY_SERVER             = 2
SSL_CERT_NOT_ON_SERVER                = 3
INCONSISTENT_FLAGS                    = 4
HYBRID_REQUIRED_BY_SERVER             = 5
SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6



class TPKT(Structure):
    commonHdr = (
        ('Version','B=3'),
        ('Reserved','B=0'),
        ('Length','>H=len(TPDU)+4'),
        ('_TPDU','_-TPDU','self["Length"]-4'),
        ('TPDU',':=""'),
    )

class TPDU(Structure):
    commonHdr = (
        ('LengthIndicator','B=len(VariablePart)+1'),
        ('Code','B=0'),
        ('VariablePart',':=""'),
    )

    def __init__(self, data = None):
        Structure.__init__(self,data)
        self['VariablePart']=''

class CR_TPDU(Structure):
    commonHdr = (
        ('DST-REF','<H=0'),
        ('SRC-REF','<H=0'),
        ('CLASS-OPTION','B=0'),
        ('Type','B=0'),
        ('Flags','B=0'),
        ('Length','<H=8'),
    )
class DATA_TPDU(Structure):
    commonHdr = (
        ('EOT','B=0x80'),
        ('UserData',':=""'),
    )

    def __init__(self, data = None):
        Structure.__init__(self,data)
        self['UserData'] =''


class RDP_NEG_REQ(CR_TPDU):
    structure = (
        ('requestedProtocols','<L'),
    )
    def __init__(self,data=None):
        CR_TPDU.__init__(self,data)
        if data is None:
            self['Type'] = TYPE_RDP_NEG_REQ

class RDP_NEG_RSP(CR_TPDU):
    structure = (
        ('selectedProtocols','<L'),
    )

class RDP_NEG_FAILURE(CR_TPDU):
    structure = (
        ('failureCode','<L'),
    )

class TSPasswordCreds(GSSAPI):
# TSPasswordCreds ::= SEQUENCE {
#         domainName  [0] OCTET STRING,
#         userName    [1] OCTET STRING,
#         password    [2] OCTET STRING
# }
   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']

   def getData(self):
       ans = pack('B', ASN1_SEQUENCE)
       ans += asn1encode( pack('B', 0xa0) +
              asn1encode( pack('B', ASN1_OCTET_STRING) +
              asn1encode( self['domainName'].encode('utf-16le'))) +
              pack('B', 0xa1) +
              asn1encode( pack('B', ASN1_OCTET_STRING) +
              asn1encode( self['userName'].encode('utf-16le'))) +
              pack('B', 0xa2) +
              asn1encode( pack('B', ASN1_OCTET_STRING) +
              asn1encode( self['password'].encode('utf-16le'))) )
       return ans

   def fromString(self, data=None):
        next_byte = unpack('B', data[:1])[0]
        if next_byte != ASN1_SEQUENCE:
            raise Exception('SEQUENCE expected')
        data = data[1:]
        decode_data , length = asn1decode(data)
        next_byte = unpack('B',decode_data[:1])[0]

        #Getting in domainName section
        if next_byte != 0xa0:
            raise Exception('0xa0 expected')
        decode_data2 , backuplength = asn1decode(decode_data[1:])
        next_byte = unpack('B', decode_data2[:1])[0]
        if next_byte != ASN1_OCTET_STRING:
            raise Exception('ASN OCTET expected')
        decode_data2, length = asn1decode(decode_data2[1:])
        self['domainName'] = decode_data2.decode('utf-16le')

        #Restoring length and moving on to username section
        decode_data = decode_data[backuplength+1:]
        next_byte = unpack('B', decode_data[:1])[0]
        if next_byte != 0xa1:
            raise Exception('0xa1 expected')
        decode_data2 , backuplength  = asn1decode(decode_data[1:])
        next_byte = unpack('B', decode_data2[:1])[0]
        if next_byte != ASN1_OCTET_STRING:
            raise Exception('ASN OCTET expected 2')
        decode_data2, length = asn1decode(decode_data2[1:])
        self['userName'] = decode_data2.decode('utf-16le')

        #Restoring length and moving on to password section
        decode_data = decode_data[backuplength+1:]
        next_byte = unpack('B', decode_data[:1])[0]
        if next_byte != 0xa2:
            raise Exception('0xa2 expected 3')
        decode_data2 , backuplength  = asn1decode(decode_data[1:])
        next_byte = unpack('B', decode_data2[:1])[0]
        if next_byte != ASN1_OCTET_STRING:
            raise Exception('ASN OCTET expected')
        decode_data2, length = asn1decode(decode_data2[1:])
        self['password'] = decode_data2.decode('utf-16le')





class TSCredentials(GSSAPI):
# TSCredentials ::= SEQUENCE {
#        credType    [0] INTEGER,
#        credentials [1] OCTET STRING
# }
   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']

   def getData(self):
     # Let's pack the credentials field
     credentials =  pack('B',0xa1)
     credentials += asn1encode(pack('B',ASN1_OCTET_STRING) +
                    asn1encode(self['credentials']))

     ans = pack('B',ASN1_SEQUENCE)
     ans += asn1encode( pack('B', 0xa0) +
            asn1encode( pack('B', 0x02) +
            asn1encode( pack('B', self['credType']))) +
            credentials)
     return ans

   def fromString(self, data=None):
       next_byte = unpack('B',data[:1])[0]
       if next_byte != ASN1_SEQUENCE:
           raise Exception('SEQUENCE expected! (%x)' % next_byte)
       data = data[1:]
       decode_data , length = asn1decode(data)
       next_byte = unpack('B',decode_data[:1])[0]
       if next_byte != 0xa0:
           raise Exception('0xa0 expected!')
       decode_data2 , backuplength = asn1decode(decode_data[1:])
       next_byte = unpack('B',decode_data2[:1])[0]
       if next_byte != 0x02:
           raise Exception('0x02 expected!')
       decode_data2 , length = asn1decode(decode_data2[1:])
       self['credType']=unpack('B',decode_data2)
       #Here, we should get back to credentials
       decode_data = decode_data[backuplength+1:]
       next_byte=unpack('B',decode_data[:1])[0]
       if next_byte != 0xa1:
           raise Exception('0xa1 expected')
       decode_data, length = asn1decode(decode_data[1:])
       next_byte = unpack('B', decode_data[:1])[0]
       if next_byte != ASN1_OCTET_STRING:
           raise Exception('ASN1 expected')
       decode_data, length = asn1decode(decode_data[1:])
       self['credentials']=decode_data






class TSRequest(GSSAPI):
# TSRequest ::= SEQUENCE {
#	version     [0] INTEGER,
#       negoTokens  [1] NegoData OPTIONAL,
#       authInfo    [2] OCTET STRING OPTIONAL,
#	pubKeyAuth  [3] OCTET STRING OPTIONAL,
#       errorCode   [4] INTEGER OPTIONAL,
#       clientNonce [5] OCTET STRING OPTIONAL
#}
#
# NegoData ::= SEQUENCE OF SEQUENCE {
#        negoToken [0] OCTET STRING
#}
#

   def __init__(self, data=None):
       GSSAPI.__init__(self,data)
       del self['UUID']

   def fromString(self, data = None):
       next_byte = unpack('B',data[:1])[0]
       if next_byte != ASN1_SEQUENCE:
           raise Exception('SEQUENCE expected! (%x)' % next_byte)
       data = data[1:]
       decode_data, total_bytes = asn1decode(data)

       next_byte = unpack('B',decode_data[:1])[0]
       if next_byte !=  0xa0:
            raise Exception('0xa0 tag not found %x' % next_byte)
       decode_data = decode_data[1:]
       next_bytes, total_bytes = asn1decode(decode_data)
       # The INTEGER tag must be here
       if unpack('B',next_bytes[0:1])[0] != 0x02:
           raise Exception('INTEGER tag not found %r' % next_byte)
       next_byte, _ = asn1decode(next_bytes[1:])
       self['Version'] = unpack('B',next_byte)[0]
       decode_data = decode_data[total_bytes:]
       next_byte = unpack('B',decode_data[:1])[0]
       if next_byte == 0xa1:
           # We found the negoData token
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           backup_length = total_bytes

           next_byte = unpack('B',decode_data2[:1])[0]
           if next_byte != ASN1_SEQUENCE:
               raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data2[1:])

           next_byte = unpack('B',decode_data2[:1])[0]
           if next_byte != ASN1_SEQUENCE:
               raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data2[1:])

           next_byte = unpack('B',decode_data2[:1])[0]
           if next_byte != 0xa0:
               raise Exception('0xa0 tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data2[1:])

           next_byte = unpack('B',decode_data2[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data2[1:])
           # the rest should be the data
           self['NegoData'] = decode_data2
           # Set decode data to the next part of the SPNEGO TOKEN
           decode_data = decode_data[backup_length+1:]
           #Check if we still have some data left. Setting next_byte for the next check in case we do.
           if len(decode_data) != 0:
              next_byte = unpack('B',decode_data[:1])[0]


       if next_byte == 0xa2:
           # ToDo: Check all this
           # We found the authInfo token
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           backup_length = total_bytes
           next_byte = unpack('B',decode_data2[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data2[1:])
           self['authInfo'] = decode_data2
           # Set decode data to the next part of the SPNEGO TOKEN
           decode_data = decode_data[backup_length+1:]
           #Check if we still have some data left. Setting next_byte for the next check in case we do.
           if len(decode_data) != 0 :
               next_byte = unpack('B',decode_data[:1])[0]

       if next_byte == 0xa3:
           # ToDo: Check all this
           # We found the pubKeyAuth token
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           backup_length = total_bytes
           next_byte = unpack('B',decode_data2[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data2[1:])
           self['pubKeyAuth'] = decode_data2
           # Set decode data to the next part of the SPNEGO TOKEN
           decode_data = decode_data[backup_length+1:]
           #Check if we still have some data left. Setting next_byte for the next check in case we do.
           if len(decode_data) != 0 :
               next_byte = unpack('B',decode_data[:1])[0]

       if next_byte == 0xa4:
           # ToDo: Check all this
           # We found an errorCode
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           backup_length = total_bytes
           next_byte = unpack('B',decode_data2[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data2[1:])
           self['errorCode'] = decode_data2
           # Set decode data to the next part of the SPNEGO TOKEN
           decode_data = decode_data[backup_length+1:]
           #Check if we still have some data left. Setting next_byte for the next check in case we do.
           if len(decode_data) != 0 :
               next_byte = unpack('B',decode_data[:1])[0]

       if next_byte == 0xa5:
           # ToDo: Check all this
           # We found an clientNonce
           decode_data2, total_bytes = asn1decode(decode_data[1:])
           backup_length = total_bytes
           next_byte = unpack('B',decode_data2[:1])[0]
           if next_byte != ASN1_OCTET_STRING:
               raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
           decode_data2, total_bytes = asn1decode(decode_data2[1:])
           self['clientNonce'] = decode_data2
           # Set decode data to the next part of the SPNEGO TOKEN
           decode_data = decode_data[backup_length+1:]
           #Check if we still have some data left. Setting next_byte for the next check in case we do.
           if len(decode_data) != 0 :
               next_byte = unpack('B',decode_data[:1])[0]




   def getData(self):
     # Do we have pubKeyAuth?
     if 'pubKeyAuth' in self.fields:
         pubKeyAuth = pack('B',0xa3)
         pubKeyAuth += asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['pubKeyAuth']))
     else:
         pubKeyAuth = b''

     if 'authInfo' in self.fields:
         authInfo = pack('B',0xa2)
         authInfo+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['authInfo']))
     else:
         authInfo = b''

     if 'clientNonce' in self.fields:
         clientNonce = pack('B',0xa5)
         clientNonce+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['clientNonce']))
     else:
         clientNonce = b''

     if 'errorCode' in self.fields:
         errorCode = pack('B',0xa4)
         errorCode+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['errorCode']))
     else:
         errorCode = b''


     if 'NegoData' in self.fields:
         negoData = pack('B',0xa1)
         negoData += asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', 0xa0) +
                    asn1encode(pack('B', ASN1_OCTET_STRING) +
                    asn1encode(self['NegoData'])))))
     else:
        negoData = b''


     if 'NegoDataKerb' in self.fields:
         negoDataKerb = pack('B',0xa1)
         negoDataKerb += asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', 0xa0) +
                    asn1encode(pack('B', 0x03) +
                    b"\x0a\x01\x01"))))
     else:
         negoDataKerb = b''

     #insert version
     if 'Version' in self.fields:
         version = asn1encode(pack('B',self['Version']))

     #if version not found, default to version 6 wich is most recent
     else:
         version = asn1encode(pack('B',0x06))

     ans = pack('B', ASN1_SEQUENCE)
     ans += asn1encode(pack('B',0xa0) +
            asn1encode(pack('B',0x02) + version) +
            negoData + negoDataKerb + authInfo + pubKeyAuth + errorCode + clientNonce)

     return ans


   def getKRBData(self):

     # Do we have pubKeyAuth?
     if 'pubKeyAuth' in self.fields:
         pubKeyAuth = pack('B',0xa3)
         pubKeyAuth += asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['pubKeyAuth']))
     else:
         pubKeyAuth = b''

     if 'authInfo' in self.fields:
         authInfo = pack('B',0xa2)
         authInfo+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['authInfo']))
     else:
         authInfo = b''

     if 'clientNonce' in self.fields:
         clientNonce = pack('B',0xa5)
         clientNonce+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['clientNonce']))
     else:
         clientNonce = b''

     if 'errorCode' in self.fields:
         errorCode = pack('B',0xa4)
         errorCode+= asn1encode(pack('B', ASN1_OCTET_STRING) +
                       asn1encode(self['errorCode']))
     else:
         errorCode = b''


     if 'NegoData' in self.fields:
         negoData = pack('B',0xa1)
         negoData += asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', 0xa0) +
                    asn1encode(pack('B', ASN1_OCTET_STRING) +
                    asn1encode(self['NegoData'])))))
     else:
        negoData = b''


     if 'NegoDataKerb' in self.fields:
         negoDataKerb = pack('B',0xa1)
         negoDataKerb += asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', ASN1_SEQUENCE) +
                    asn1encode(pack('B', 0xa0) +
                    asn1encode(pack('B', 0x03) +
                    b"\x0a\x01\x01"))))
     else:
         negoDataKerb = b''

     #insert version
     if 'Version' in self.fields:
         version = asn1encode(pack('B',self['Version']))

     #if version not found, default to version 6 wich is most recent
     else:
         version = asn1encode(pack('B',0x06))

     ans = pack('B', ASN1_SEQUENCE)
     ans += asn1encode(pack('B',0xa0) +
            asn1encode(pack('B',0x0a) + version) +
            authInfo + pubKeyAuth + errorCode + clientNonce)
     realans = pack('B',0xa1) + asn1encode(ans)
     return realans

class SPNEGOCipher:
        def __init__(self, flags, randomSessionKey):
            self.__flags = flags
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                self.__clientSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey)
                self.__serverSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey,"Server")
                self.__clientSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey)
                self.__serverSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey,"Server")
                # Preparing the keys handle states
                cipher3 = ARC4.new(self.__clientSealingKey)
                self.__clientSealingHandle = cipher3.encrypt
                cipher4 = ARC4.new(self.__serverSealingKey)
                self.__serverSealingHandle = cipher4.encrypt
            else:
                # Same key for everything
                self.__clientSigningKey = randomSessionKey
                self.__serverSigningKey = randomSessionKey
                self.__clientSealingKey = randomSessionKey
                self.__clientSealingKey = randomSessionKey
                cipher = ARC4.new(self.__clientSigningKey)
                self.__clientSealingHandle = cipher.encrypt
                self.__serverSealingHandle = cipher.encrypt
            self.__sequence = 0

        def serverEncrypt(self, plain_data):
            self.__sequence = 0
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                # When NTLM2 is on, we sign the whole pdu, but encrypt just
                # the data, not the dcerpc header. Weird..
                sealedMessage, signature =  ntlm.SEAL(self.__flags,
                       self.__serverSigningKey,
                       self.__serverSealingKey,
                       plain_data,
                       plain_data,
                       self.__sequence,
                       self.__serverSealingHandle)
            else:
                sealedMessage, signature =  ntlm.SEAL(self.__flags,
                       self.__serverSigningKey,
                       self.__serverSealingKey,
                       plain_data,
                       plain_data,
                       self.__sequence,
                       self.__clientSealingHandle)

            self.__sequence += 1
            return signature, sealedMessage

        def clientEncrypt(self, plain_data):
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                # When NTLM2 is on, we sign the whole pdu, but encrypt just
                # the data, not the dcerpc header. Weird..
                sealedMessage, signature =  ntlm.SEAL(self.__flags,
                       self.__clientSigningKey,
                       self.__clientSealingKey,
                       plain_data,
                       plain_data,
                       self.__sequence,
                       self.__clientSealingHandle)
            else:
                sealedMessage, signature =  ntlm.SEAL(self.__flags,
                       self.__clientSigningKey,
                       self.__clientSealingKey,
                       plain_data,
                       plain_data,
                       self.__sequence,
                       self.__clientSealingHandle)

            self.__sequence += 1
            return signature, sealedMessage


        def decrypt(self, answer):
            if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                # TODO: FIX THIS, it's not calculating the signature well
                # Since I'm not testing it we don't care... yet
                answer, signature =  ntlm.SEAL(self.__flags,
                        self.__serverSigningKey,
                        self.__serverSealingKey,
                        answer,
                        answer,
                        self.__sequence,
                        self.__serverSealingHandle)
            else:
                answer, signature = ntlm.SEAL(self.__flags,
                        self.__serverSigningKey,
                        self.__serverSealingKey,
                        answer,
                        answer,
                        self.__sequence,
                        self.__serverSealingHandle)
                self.__sequence += 1

            return signature, answer

