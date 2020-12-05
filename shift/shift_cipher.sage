#!/usr/bin/env sage

from ngram_score import ngram_score
import re
import os

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
CWD_PATH = os.getcwd()

fitness = ngram_score(DIR_PATH + "/quadgrams.txt")


class ShiftCipher:
    """Shift Cipher Class

    This will encrypt/decrypt any alphabetic string (white spaces are also
    allowed) in case sensitive form using Shift Cipher algorithm. Incase any
    special characters are inputted, it will not encrypt it and it will be
    included in the cipher text (incase of encrypting) and plain text (incase
    of decrypting).

    Example :
        Plain Text : HELLO
        key : 3

        Cipher Text : KHOOR
    """

    @staticmethod
    def decrypt(cipher, key):
        """Returns the decrypted plain text of the given cipher text encrypted
        with `key`

        Args:
            cipher (str): Cipher text or the encrypted text to be decrypted.
            It should contain only UPPERCASE alphabets. Non-alphabetical
            characters will be ignored.

            key (int): Key used for decrypting the shift cipher.

        Returns:
            result (str): Plain text or the original unencrypted message
        """
        result = ""

        for i in range(len(cipher)):

            idx = ord(cipher[i]) - ord("A")
            encr_char = (idx - key) % 26 + ord("A")
            result += chr(encr_char)

        return result

    @staticmethod
    def encrypt(plain_text, key):
        """Returns the cipher text encrypted with `key` using Shift Cipher Algoirthm

        Args:
            plain_text (str): Message to be encrypted. It should contain only
            UPPERCASE alphabets. Non-alphabetical characters will be ignored.

            key (int): Key to encrypt the plaintext.

        Returns:
            result (str): Encrypted message or the cipher text
        """
        result = ""

        for i in range(len(plain_text)):

            idx = ord(plain_text[i]) - ord("A")
            encr_char = (idx + key) % 26 + ord("A")
            result += chr(encr_char)

        return result


class Cryptanalysis:
    @staticmethod
    def chosen_ciphertext(cipher_text, decryption_key):
        """We have access to decryption algorithm in this technique"""

        chosen_cipher = "Z"
        decrypted_chr = ShiftCipher.decrypt(chosen_cipher, decryption_key)
        key = abs(ord(chosen_cipher) - ord(decrypted_chr))

        return ShiftCipher.decrypt(cipher_text, key)

    @staticmethod
    def chosen_plaintext(cipher_text, encryption_key):
        """We have access to encryption algorithm in this technique"""

        chosen_plain = "A"
        encrypted_chr = ShiftCipher.encrypt(chosen_plain, encryption_key)
        key = abs(ord(encrypted_chr) - ord(chosen_plain))

        return ShiftCipher.decrypt(cipher_text, key)

    @staticmethod
    def known_plaintext(prev_plain_text, prev_cipher_text, cipher_text):
        key = abs(ord(prev_cipher_text[0]) - ord(prev_plain_text[0])) % 26
        return ShiftCipher.decrypt(cipher_text, key)

    @staticmethod
    def ciphertext_only(ciphertext):

        scores = []
        for i in range(26):
            scores.append(
                (fitness.score(ShiftCipher.decrypt(cipher_text, i)), i)
            )  # try all possible keys, return the one with the highest fitness
        max_key = max(scores)
        return ShiftCipher.decrypt(cipher_text, max_key[1])


if __name__ == "__main__":
    """
    Driver function

    Program Input/Output Specifications :

    * The INPUT file must be named `input.txt` and each line would be the test
    cases in the format :
                                        A,B,C,D...

    * If A is 1 (Encryption), B = key and C = Plaintext

    * If A is 2 (Decryption), B = key and C = Ciphertext

    * If A is 3 (Chosen Ciphertext attack), B = key, C = Ciphertext

    * If A is 4 (Chosen plaintext attack), B = key, C = Ciphertext

    * If A is 5 (Known plaintext attack), B = Prev. Plaintext, C = Prev. Ciphertext, D = Ciphertext

    * If A is 6 (Ciphertext only attack), B = Ciphertext

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
            key = int(opts[1])
            if key >= -26 and key <= 26:
                plain_text = opts[2]
                plain_text = re.sub(
                    "[^A-Z]", "", plain_text.upper()
                )  # remove special characters and convert to UPPERCASE
                cipher_text = ShiftCipher.encrypt(plain_text, abs(key))
                output_file.write(cipher_text + "\n")
            else:
                output_file.write("-1\n")

        elif option == 2:  # decryption
            key = int(opts[1])
            if key >= -26 and key <= 26:
                cipher_text = opts[2]
                cipher_text = re.sub(
                    "[^A-Z]", "", cipher_text.upper()
                )  # remove special characters and convert to UPPERCASE
                plain_text = ShiftCipher.decrypt(cipher_text, abs(key))
                output_file.write(plain_text + "\n")
            else:
                output_file.write("-1\n")

        elif option == 3:  # chosen ciphertext

            decryption_key = int(opts[1])

            cipher_text = re.sub(
                "[^A-Z]", "", opts[2].upper()
            )  # remove special characters and convert to UPPERCASE

            plain_text = Cryptanalysis.chosen_ciphertext(
                cipher_text, decryption_key
            )

            output_file.write(plain_text + "\n")

        elif option == 4:  # chosen plaintext

            encryption_key = int(opts[1])

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
