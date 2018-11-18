import OpenSSL
import argparse
import re
import requests

''' 
Arguments to add:
    pass the path by argument
    read the doc carefully
    bla
'''

class Verifier:

    def __init__(self, path):
        '''
        Constructor of the class. Every instance of the class
        will need to be initialized with a given parameter, poiting
        to the certificate.
        '''
        self.path = path


    def __load_certificate(self):
        self.__cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, 
                        open(self.path).read()
        )

        return self.__cert


    # Delete #
    def get_signature_algorithm(self):
        self.algorithm = self.__load_certificate().get_signature_algorithm()

        return self.algorithm


    # Delete #
    def dump(self):
        self.cert_dumped = OpenSSL.crypto.dump_certificate(
                            OpenSSL.crypto.FILETYPE_TEXT, 
                            self.__load_certificate())

        return self.cert_dumped

    
    def get_extension(self):
        '''
        This method return informations about the AIA - Authority Information Access
        With this, we can extract the link of the Sub CA.
        '''
        # The index 7 in get_extension() is a simply guess. How to know and retrieve in a ok manner?
        # Dont know
        self.extension = self.__load_certificate().get_extension(7).__str__()

        return self.extension


    def get_link_from_extension(self):
        '''
        Method that uses regex to extract the link from the AIA - Authority Information Access
        and download the certificate of the Sub CA.
        '''
        self.url_string = self.get_extension()
        # Maaaan i dont know... I think it will break with other certificates
        self.pattern = re.compile(r'(http:\/\/)+?[a-z]+\.[a-z]+\.[a-z]+\/\w+\.crt')
        self.match = self.pattern.search(self.url_string)

        if self.match:
            self.name = self.match.group(0)
            return self.name
        else:
            raise Exception('Pattern not found')

    
    def get_certificate_SubCA(self):
        self.get = requests.get(self.get_link_from_extension(), allow_redirects=True)
        open('Sub-CA.crt', 'wb').write(self.get.content)

    def check_SubCA_Root(self):
        # TODO
        return None