import re
import tqdm
import math
import OpenSSL
import requests


class Verifier:

    def __init__(self, file, rootCA):
        self.file = file
        self.rootCA = rootCA

    def __load_certificate(self):
        # Determine if the certificate is PEM or ASN1
        try: # Verify if is in PEM format
            self.__cert = OpenSSL.crypto.load_certificate(
                            OpenSSL.crypto.FILETYPE_PEM,
                            open(self.file).read()
            )
        except: # ASN1 format
            self.__cert = OpenSSL.crypto.load_certificate(
                            OpenSSL.crypto.FILETYPE_ASN1,
                            open(self.file).read()
            )

        return self.__cert

    def getSignatureAlgorithm(self):
        self.algorithm = self.__load_certificate().get_signature_algorithm()

        return self.algorithm

    def getExtensionAIA(self):
        self.SubCA_link = re.compile('^CA\sIssuers\s\-\sURI(.*)$', re.MULTILINE)
        self.numExtensions = self.__load_certificate().get_extension_count()
        self.cert = self.__load_certificate()
        self.aia = ''
        for i in range(0, self.numExtensions):
            self.current_extension = self.cert.get_extension(i)
            if self.current_extension.get_short_name() == b'authorityInfoAccess':
                self.aia = str(self.current_extension)
                self.match = self.SubCA_link.search(self.aia)

                if self.match:
                    # Need only to get the link
                    self.link = self.match.group(0)
                    self.link_clean = self.link.replace('CA Issuers - URI:', '')
                    return self.link_clean
                else:
                    raise Exception('Link not found')

        return self.aia

    def getCertificateSubCA(self):
        self.get = requests.get(self.getExtensionAIA(), allow_redirects=True, stream=True)
        open('SubCA', 'wb').write(self.get.content)

    def __load_SubCertificate(self):
        '''
        Since we dowloaded and wrote the SubCA certificate as binary mode,
        we need to open as binary mode.
        '''
        self.file = 'SubCA'
        try: # Verify if is in PEM format
            self.__cert_subCA = OpenSSL.crypto.load_certificate(
                                    OpenSSL.crypto.FILETYPE_PEM,
                                    open(self.file, 'rb').read()
            )

        except: # ASN1 format
            self.__cert_subCA = OpenSSL.crypto.load_certificate(
                                    OpenSSL.crypto.FILETYPE_ASN1,
                                    open(self.file, 'rb').read()
            )

        return self.__cert_subCA

    def getExtensionAuthorityKey(self):
        self.numExtensions = self.__load_SubCertificate().get_extension_count()
        self.subCert = self.__load_SubCertificate()
        self.authKey = ''
        for i in range(0, self.numExtensions):
            self.current_extension = self.subCert.get_extension(i)
            if self.current_extension.get_short_name() == b'authorityKeyIdentifier':
                self.authKey = str(self.current_extension).replace(':', '').replace('keyid', '').lower()

        return self.authKey

    def __load_RootCA(self):
        try: # Verify if is in PEM format
            self.__cert_RootCA = OpenSSL.crypto.load_certificate(
                                    OpenSSL.crypto.FILETYPE_PEM,
                                    open(self.rootCA, 'rb').read()
            )

        except: # ASN1 format
            self.__cert_RootCA = OpenSSL.crypto.load_certificate(
                                    OpenSSL.crypto.FILETYPE_ASN1,
                                    open(self.rootCA, 'rb').read()
            )
        return self.__cert_RootCA

    def getExtensionAuthorityKey_RootCA(self):
        self.RootCA = self.__load_RootCA()
        self.numExtensions = self.RootCA.get_extension_count()
        self.authKey_RootCA = ''
        for i in range(0, self.numExtensions):
            self.current_extension = self.RootCA.get_extension(i)
            if self.current_extension.get_short_name() == b'authorityKeyIdentifier':
                self.authKey_RootCA = str(self.current_extension).replace(':', '').replace('keyid', '').lower()

        return self.authKey_RootCA

    def check_SubCA_Root(self):
        if self.getExtensionAuthorityKey() == self.getExtensionAuthorityKey_RootCA():
            return 'I can trust this certificate!'
        else:
            return 'I can\'t trust this certifcate'
