from Verifier import Verifier

def main():
    verifier = Verifier('wordpresscom.crt')
    print('Signature Algorithm of the Certificate: {}'.
    format(verifier.get_signature_algorithm()
                    .decode('utf-8'))
    )
    verifier.get_extension_AIA()
    verifier.get_link_from_extension()
    verifier.get_certificate_SubCA()
    print(verifier.get_extension_AuthorityKey())
    print(verifier.check_SubCA_Root())
    dumped = verifier.dump().decode('utf-8').replace('\n', '')
    path = 'dump.txt'
    dumped_file = open(path, 'w')
    dumped_file.write(dumped)
    dumped_file.close()

if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        print('Interrupt received from keyboard! Exiting...')