#!/usr/bin/env sage

import os
import re
from itertools import permutations
from classical_ciphers.utils.ngram_score import ngram_score


BOGUS_CHARACTER = "Z"
DIR_PATH = os.path.dirname(os.path.realpath(__file__))
CWD_PATH = os.getcwd()

fitness = ngram_score(CWD_PATH + "/classical_ciphers/utils/quadgrams.txt")


class KeyedTransposition:
    """Keyed Transposition Class

    This will encrypt any alphabetic string (white spaces are also allowed) in
    case sensitive form using Keyed Transposition algorithm.

    Example :
        Plain Text : ENEMYATTACKSTONIGHT
        Key : 31452

        Cipher Text : EEMYNTAACTTKONSHITZG
    """

    @staticmethod
    def split_len(seq, length):
        x = []
        for i in range(0, len(seq), length):
            part = seq[i : i + length]
            if (len(part) % length) != 0:
                for j in range(len(part) % length, length):
                    part += BOGUS_CHARACTER
            x.append(part)
        return x

    @staticmethod
    def encrypt(plain_text, key):
        """Returns the cipher text encrypted using Keyed Transposition Cipher Algoirthm

        Args:
            plain_text (str): Message to be encrypted. It should contain only
            alphabets.
            key (list(int)): Key used for decrypting the transposition cipher.
            It should contain digits in list format

        Returns:
            result (str): Encrypted message or the cipher text
        """
        result = ""

        order = {num: val - 1 for num, val in enumerate(key)}

        parts = KeyedTransposition.split_len(plain_text, len(key))
        for part in parts:
            for index in order.keys():
                try:
                    result += part[order[index]]
                except IndexError:
                    continue

        return result

    @staticmethod
    def decrypt(cipher_text, key):
        """Returns the plain text decrypted using Keyed Transposition Cipher Algoirthm

        Args:
            cipher_text (str): Cipher text or the encrypted text to be
            decrypted. It should contain only alphabets.
            key (list(int)): Key used for encryption in transposition cipher.
            It should contain digits in list format.

        Returns:
            result (str): Plain text or the original unencrypted message
        """
        result = ""

        order = {val - 1: num for num, val in enumerate(key)}

        parts = KeyedTransposition.split_len(cipher_text, len(key))
        for part in parts:
            for index in sorted(order.keys()):
                try:
                    result += part[order[index]]
                except IndexError:
                    continue

        # bogus_count = result.count(BOGUS_CHARACTER)

        # if bogus_count > 0:
        #     return result[:-bogus_count]

        return result


class Cryptanalysis:
    @staticmethod
    def chosen_ciphertext(cipher_text, decryption_key):
        """We have access to decryption algorithm in this technique"""
        plain_text = "-1"
        chosen_cipher = "A"
        KLEN = len(KeyedTransposition.decrypt(chosen_cipher, decryption_key))
        match_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:KLEN]
        for perm in list(permutations("ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:KLEN])):
            chosen_cipher = "".join(perm)

            decrypted_msg = KeyedTransposition.decrypt(
                chosen_cipher, decryption_key
            )
            if match_str == decrypted_msg:
                break

        key = []
        for i in range(0, KLEN):
            key.append(ord(chosen_cipher[i]) - ord("A") + 1)

        plain_text = KeyedTransposition.decrypt(cipher_text, key)

        return plain_text

    @staticmethod
    def chosen_plaintext(cipher_text, encryption_key):
        """We have access to encryption algorithm in this technique"""
        plain_text = "-1"
        KLEN = len(KeyedTransposition.encrypt("A", encryption_key))

        chosen_plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[0:KLEN]
        encr_msg = KeyedTransposition.encrypt(chosen_plain, encryption_key)
        key = []
        for i in range(0, KLEN):
            key.append(ord(encr_msg[i]) - ord("A") + 1)

        # print(key)
        plain_text = KeyedTransposition.decrypt(cipher_text, key)
        return plain_text

    @staticmethod
    def known_plaintext(prev_plain_text, prev_cipher_text, cipher_text):
        plain_text = "-1"
        for i in range(3, 11):  # KLEN 3 to 11
            print("KLEN" + str(i - 1))
            for permute in list(permutations(range(1, i))):

                """ TODO : Might have to handle error here. """
                decrypted_msg = KeyedTransposition.decrypt(
                    prev_cipher_text, permute
                )
                if decrypted_msg == prev_plain_text:
                    key = permute
                    break

        plain_text = KeyedTransposition.decrypt(cipher_text, key)
        return plain_text

    @staticmethod
    def ciphertext_only(ciphertext):
        plain_text = -1
        scores = []
        for i in range(3, 11):  # KLEN 3 to 11
            print("KLEN " + str(i - 1))
            for permute in list(permutations(range(1, i))):
                list_perm = list(permute)

                """ TODO : Might have to handle error here. """
                scores.append(
                    (
                        fitness.score(
                            KeyedTransposition.decrypt(cipher_text, list_perm)
                        ),
                        permute,
                    )
                )

        key = list(max(scores)[1])

        plain_text = KeyedTransposition.decrypt(cipher_text, key)
        return plain_text


if __name__ == "__main__":
    """
    Driver function


    Program Input/Output Specifications :

    * The INPUT file must be named `input.txt` and each line would be the test
    cases in the format :
                                        A,B,C
        - A is the integer denoting Encryption or Decryption. 1 is for
         Encryption. 2 is for Decryption.
        - B denotes the key used to encrypt/decrypt.
        - C denotes the message to encrypt or decrypt.

    * The OUTPUT file will contain the results of all the test cases seperated
    by newlines in the order
    given in the input file. The name of the output file will be `output.txt`.
    Incase of invalid input, the output of that particular testcase will be -1.
    """

    input_file = open(DIR_PATH + "/input.txt", "r")
    output_file = open(DIR_PATH + "/output.txt", "w")

    for line in input_file:
        opts = [x.strip() for x in line.split(",")]
        option = int(opts[0])

        if option == 1:
            plain_text = cipher_text = re.sub("[^A-Z]", "", opts[2].upper())
            key = list(map(int, opts[1]))

            cipher_text = KeyedTransposition.encrypt(plain_text, key)

            output_file.write(cipher_text + "\n")

        elif option == 2:
            cipher_text = cipher_text = re.sub("[^A-Z]", "", opts[2].upper())
            key = list(map(int, opts[1]))

            plain_text = KeyedTransposition.decrypt(cipher_text, key)

            output_file.write(plain_text + "\n")

        elif option == 3:  # chosen ciphertext

            decryption_key = list(map(int, opts[1]))

            cipher_text = re.sub(
                "[^A-Z]", "", opts[2].upper()
            )  # remove special characters and convert to UPPERCASE

            plain_text = Cryptanalysis.chosen_ciphertext(
                cipher_text, decryption_key
            )

            output_file.write(plain_text + "\n")

        elif option == 4:  # chosen plaintext

            encryption_key = list(map(int, opts[1]))

            cipher_text = re.sub("[^A-Z]", "", opts[2].upper())

            plain_text = Cryptanalysis.chosen_plaintext(
                cipher_text, encryption_key
            )

            output_file.write(plain_text + "\n")

        elif option == 5:  # known plaintext

            prev_plain_text = re.sub("[^A-Z]", "", opts[1].upper())

            prev_cipher_text = re.sub("[^A-Z]", "", opts[2].upper())

            cipher_text = re.sub("[^A-Z]", "", opts[3].upper())

            plain_text = Cryptanalysis.known_plaintext(
                prev_plain_text, prev_cipher_text, cipher_text
            )

            output_file.write(plain_text + "\n")

        elif option == 6:  # ciphertext only

            cipher_text = re.sub("[^A-Z]", "", opts[1].upper())

            plain_text = Cryptanalysis.ciphertext_only(cipher_text)

            output_file.write(plain_text + "\n")
