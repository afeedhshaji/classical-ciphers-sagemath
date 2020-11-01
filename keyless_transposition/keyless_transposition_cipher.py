#!/usr/bin/env sage

from classical_ciphers.utils.ngram_score import ngram_score
import math
import re
import os

BOGUS_CHARACTER = "Z"

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
CWD_PATH = os.getcwd()

fitness = ngram_score(CWD_PATH + "/classical_ciphers/utils/quadgrams.txt")


class KeylessTransposition:
    """Keyless Transposition Class

    This will encrypt any alphabetic string (white spaces are also allowed) in case sensitive form using Keyless
    Transposition algorithm.

    Example :
        Plain Text : MEETMEATTHEPARK
        Columns : 4

        Cipher Text : MMTAEEHREAEKTTP
    """

    @staticmethod
    def encrypt(plain_text, num_cols):
        """Returns the cipher text encrypted using Keyless Transposition Cipher Algoirthm

        Args:
            plain_text (str): The plain text or the unecnrypted message.
            num_cols (int): Number of columns in the keyless transposition cipher technique.

        Returns:
            result (str): The encrypted message.
        """
        result = ""

        plain_text_len = len(plain_text)
        col = num_cols
        row = int(math.ceil(plain_text_len / col))

        plain_text_list = [BOGUS_CHARACTER for i in range(int(row * col))]
        plain_text_list[0:plain_text_len] = list(plain_text)

        matrix = []
        for i in range(0, len(plain_text_list), col):
            matrix.append(plain_text_list[i : i + col])

        for i in range(col):
            for j in range(row):
                result += matrix[j][i]
        return result

    @staticmethod
    def decrypt(cipher_text, num_cols):
        """Returns the decrypted plain text of the given cipher text.

        Args:
            cipher_text (str): The encrypted message
            num_cols (int): Number of columns in the keyless transposition cipher technique.

        Returns:
            result (str): The plain text or the decrypted message
        """
        plain_text = ""

        cipher_len = float(len(cipher_text))
        cipher_list = list(cipher_text)

        col = num_cols
        row = int(math.ceil(cipher_len / col))

        plain_text_matrix = []
        for _ in range(row):
            plain_text_matrix += [[BOGUS_CHARACTER] * col]

        idx = 0
        for i in range(col):
            for j in range(row):
                if idx >= cipher_len:
                    break
                plain_text_matrix[j][i] = cipher_list[idx]
                idx += 1

        plain_text = "".join(sum(plain_text_matrix, []))

        return plain_text


class Cryptanalysis:
    @staticmethod
    def chosen_ciphertext(cipher_text, decryption_cols):
        """We have access to decryption algorithm in this technique"""
        plain_text = "-1"
        chosen_cipher = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        decr_chosen_cipher = KeylessTransposition.decrypt(
            chosen_cipher, decryption_cols
        )

        min_len = min(len(chosen_cipher), len(decr_chosen_cipher))

        for num_cols in range(1, len(chosen_cipher)):
            decryption = KeylessTransposition.decrypt(chosen_cipher, num_cols)
            if decryption[:min_len] == decr_chosen_cipher[:min_len]:
                break

        plain_text = KeylessTransposition.decrypt(cipher_text, num_cols)
        return plain_text

    @staticmethod
    def chosen_plaintext(cipher_text, encryption_cols):
        """We have access to encryption algorithm in this technique"""
        plain_text = "-1"
        chosen_plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        encr_chosen_plain = KeylessTransposition.encrypt(
            chosen_plain, encryption_cols
        )

        min_len = min(len(chosen_plain), len(encr_chosen_plain))

        for num_cols in range(1, len(encr_chosen_plain)):
            decryption = KeylessTransposition.decrypt(
                encr_chosen_plain, num_cols
            )
            if decryption[:min_len] == chosen_plain[:min_len]:
                break

        plain_text = KeylessTransposition.decrypt(cipher_text, num_cols)
        return plain_text

    @staticmethod
    def known_plaintext(prev_plain_text, prev_cipher_text, cipher_text):

        plain_text = "-1"
        min_len = min(len(prev_cipher_text), len(prev_plain_text))
        for num_cols in range(1, len(cipher_text)):
            decryption = KeylessTransposition.decrypt(
                prev_cipher_text, num_cols
            )
            if decryption[:min_len] == prev_plain_text[:min_len]:
                break

        plain_text = KeylessTransposition.decrypt(cipher_text, num_cols)
        return plain_text

    @staticmethod
    def ciphertext_only(ciphertext):
        plain_text = "-1"
        scores = []
        for i in range(1, len(cipher_text)):
            scores.append(
                (
                    fitness.score(
                        KeylessTransposition.decrypt(cipher_text, i)
                    ),
                    i,
                )
            )  # try all possible keys, return the one with the highest fitness
        num_cols = max(scores)
        plain_text = KeylessTransposition.decrypt(
            cipher_text, int(num_cols[1])
        )
        return plain_text


if __name__ == "__main__":
    """
    Driver function

    Program Input/Output Specifications :

    * The INPUT file must be named `input.txt` and each line would be the test
    cases in the format :
                                        A,B,C,D...

    * If A is 1 (Encryption), B = No: of cols and C = Plaintext

    * If A is 2 (Decryption), B = No: of cols and C = Ciphertext

    * The OUTPUT file will contain the results of all the test cases seperated
    by newlines in the order given in the input file. The name of the output
    file will be `output.txt`. Incase of invalid input, the output of that
    particular testcase will be -1.
    """

    input_file = open(DIR_PATH + "/input.txt", "r")
    output_file = open(DIR_PATH + "/output.txt", "w")

    for line in input_file:
        opts = [x.strip() for x in line.split(",")]
        option = int(opts[0])

        if option == 1:  # encryption
            num_cols = int(opts[1])
            plain_text = re.sub("[^A-Z]", "", opts[2].upper())
            cipher_text = KeylessTransposition.encrypt(plain_text, num_cols)
            output_file.write(cipher_text + "\n")

        elif option == 2:  # decryption
            num_cols = int(opts[1])
            cipher_text = re.sub("[^A-Z]", "", opts[2].upper())
            plain_text = KeylessTransposition.decrypt(cipher_text, num_cols)
            output_file.write(plain_text + "\n")

        elif option == 3:  # chosen ciphertext

            num_cols = int(opts[1])

            cipher_text = re.sub(
                "[^A-Z]", "", opts[2].upper()
            )  # remove special characters and convert to UPPERCASE

            plain_text = Cryptanalysis.chosen_ciphertext(cipher_text, num_cols)

            output_file.write(plain_text + "\n")

        elif option == 4:  # chosen plaintext

            num_cols = int(opts[1])

            cipher_text = re.sub("[^A-Z]", "", opts[2].upper())

            plain_text = Cryptanalysis.chosen_plaintext(cipher_text, num_cols)

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