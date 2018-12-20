from Verifier_refactor import Verifier
import argparse

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--file', '-f', help='Name of the File', type=str)
    parser.add_argument('--rootCA', '-r', help='Name of the Root CA', type=str)
    args = parser.parse_args()

    verifier = Verifier(args.file, args.rootCA)
    print('Signature Algorithm of the Certificate: {}'.
            format(verifier.getSignatureAlgorithm()
            .decode('utf-8'))
    )
    print('Authority Information Access: {}'.
            format(verifier.getExtensionAIA())
    )
    verifier.getCertificateSubCA()
    verifier.getExtensionAuthorityKey()
    verifier.getExtensionAuthorityKey_RootCA()
    print(verifier.check_SubCA_Root())

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interruption received from keyboard! Exiting...')
