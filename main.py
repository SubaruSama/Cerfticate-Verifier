from Verifier import Verifier
import argparse

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--path', '-p', help='path to the container', type=str)
    parser.add_argument('--file', '-f', help='name of the file', type=str)
    parser.add_argument('--path_rootca', '-pra', help='location of the Root CA', type=str)
    parser.add_argument('--file_rootca', '-fra', help='file of the Root CA', type=str)
    args = parser.parse_args()

    full_path = args.path + '\\' + args.file
    full_path_rootca = args.path_rootca + '\\' + args.file_rootca

    verifier = Verifier(full_path, full_path_rootca)
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