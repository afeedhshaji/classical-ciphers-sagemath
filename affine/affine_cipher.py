#!/usr/bin/env sage

from classical_ciphers.utils.ngram_score import ngram_score
import math
import gmpy2
import os
import re


DIR_PATH = os.path.dirname(os.path.realpath(__file__))
CWD_PATH = os.getcwd()

fitness = ngram_score(CWD_PATH + "/classical_ciphers/utils/quadgrams.txt")


class AffineCipher:
    """Affine Cipher Class

    This will encrypt any alphabetic string (white spaces are also allowed) in
    UPPER CASE only form using Affine Cipher algorithm. Incase any special
    characters are inputted, it will not encrypt it and it will be included in
    the cipher text (incase of encrypting) and plain text (incase of
    decrypting). For the encryption or decryption to be possible, the key1
    should have a multiplicative inverse in Z_26 and key2 should be between
    -26 and +26.

    Example :
        Plain Text : WELCOME
        Key 1 : 15
        Key 2 : 8

        Cipher Text : AQRMKGQ
    """

    @staticmethod
    def encrypt(plain_text, key1, key2):
        """Returns the cipher text encrypted with `key 1` and `key 2` using
        Affine Cipher Algoirthm

        Args:
            plain_text (str): Message to be encrypted. Alphabets should be in
            UPPERCASE. Non-alphabetical characters will not be encrypted.
            key1 (int): Key 1 should have a multiplicative inverse in Z_26 or
            gcd(key1, 26) = 1.
            key2 (int): Key 2 should be between 26 and -26

        Returns:
            result (str): Encrypted message or the cipher text
        """
        result = ""

        for i in range(len(plain_text)):
            idx = ord(plain_text[i]) - ord("A")
            new_idx = ((idx * key1) + key2) % 26
            encr_char = chr(new_idx + ord("A"))
            result += encr_char

        return result

    @staticmethod
    def decrypt(cipher_text, key1, key2):
        """Returns the decrypted plain text of the given cipher text encrypted
        with `key 1` and `key 2`

        Args:
            cipher_text (str): Cipher text or the encrypted text to be
            decrypted. Alphabets should be UPPERCASE.
            Non-alphabetical characters will not be decrypted.
            key1 (int): Key 1 should have a multiplicative inverse in Z_@6 or
            gcd(key1, 26) = 1.
            key2 (int): Key 2 should be between 26 and -26

        Returns:
            result (str): Plain text or the original unencrypted message
        """
        result = ""

        for i in range(len(cipher_text)):
            idx = ord(cipher_text[i]) - ord("A")
            old_idx = (gmpy2.invert(key1, 26) * (idx - key2)) % 26
            encr_char = chr(old_idx + ord("A"))
            result += encr_char

        return result


class Cryptanalysis:
    @staticmethod
    def chosen_ciphertext(cipher_text, decryption_key1, decryption_key2):
        for i in range(26):
            idx = ord("A") + i
            decrypted_chr = AffineCipher.decrypt(
                chr(idx), decryption_key1, decryption_key2
            )
            if decrypted_chr == "A":
                key2 = i
                break

        # Bruteforcing to find key1
        chosen_cipher = "AQRMKGQ"
        for i in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            decrypted_msg = AffineCipher.decrypt(chosen_cipher, i, key2)
            """
            LHS is the attacker's trial and error decryption key used in the
            algorithm.
            RHS is the original decryption algorithm the attacker has access
            to.
            """
            if decrypted_msg == AffineCipher.decrypt(
                chosen_cipher, decryption_key1, decryption_key2
            ):
                key1 = i
                break

        return AffineCipher.decrypt(cipher_text, key1, key2)

    @staticmethod
    def chosen_plaintext(cipher_text, encryption_key1, encryption_key2):
        """We have access to encryption algorithm in this technique"""
        chosen_plain1 = "A"
        chosen_plain2 = "B"

        key2 = ord(
            AffineCipher.encrypt(
                chosen_plain1, encryption_key1, encryption_key2
            )
        ) - ord("A")
        key1 = (
            ord(
                AffineCipher.encrypt(
                    chosen_plain2, encryption_key1, encryption_key2
                )
            )
            - ord("A")
            - key2
        )

        return AffineCipher.decrypt(cipher_text, key1, key2)

    @staticmethod
    def known_plaintext(prev_plain_text, prev_cipher_text, cipher_text):
        """ Bruteforcing all the possibilites"""
        for k1 in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            for k2 in range(25):
                decrypted_text = AffineCipher.decrypt(prev_cipher_text, k1, k2)
                if decrypted_text == prev_plain_text:
                    return AffineCipher.decrypt(cipher_text, k1, k2)

    @staticmethod
    def ciphertext_only(cipher_text):

        scores = []
        for i in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            scores.extend(
                [
                    (
                        fitness.score(AffineCipher.decrypt(cipher_text, i, j)),
                        (i, j),
                    )
                    for j in range(0, 25)
                ]
            )
        max_key = max(scores)
        return AffineCipher.decrypt(cipher_text, max_key[1][0], max_key[1][1])


if __name__ == "__main__":
    """
    Driver function

    Program Input/Output Specifications :

    * The INPUT file must be named `input.txt` and each line would be the test
    cases in the format :
                                        A,B,C,D
        - A is the integer denoting Encryption or Decryption. 1 is for
         Encryption. 2 is for Decryption.
        - B denotes the key1 used to encrypt/decrypt.
        - C denotes the key2 used to encrypt/decrypt.
        - D denotes the message to encrypt or decrypt.

    * The OUTPUT file will contain the results of all the test cases seperated
    by newlines in the order given in the input file. The name of the output
    file will be `output.txt`. Incase of invalid input, the output of that
    particular testcase will be -1.
    """
    affine_cipher = AffineCipher()

    input_file = open(DIR_PATH + "/input.txt", "r")
    output_file = open(DIR_PATH + "/output.txt", "w")

    for line in input_file:
        opts = [x.strip() for x in line.split(",")]
        option = int(opts[0])

        if option == 1:
            key1 = int(opts[1])
            key2 = abs(int(opts[2]))
            if math.gcd(key1, 26) == 1:
                if key2 <= 26 and key2 >= 0:
                    plain_text = opts[3]
                    plain_text = re.sub("[^A-Z]", "", plain_text.upper())
                    cipher_text = AffineCipher.encrypt(plain_text, key1, key2)
                    output_file.write(cipher_text + "\n")
                else:
                    output_file.write("-1\n")
            else:
                output_file.write("-1\n")

        elif option == 2:
            key1 = int(opts[1])
            key2 = abs(int(opts[2]))
            if math.gcd(key1, 26) != 1:
                output_file.write("-1\n")
            else:
                if key2 <= 26 and key2 >= 0:
                    cipher_text = opts[3]
                    cipher_text = re.sub("[^A-Z]", "", cipher_text.upper())
                    plain_text = AffineCipher.decrypt(cipher_text, key1, key2)
                    output_file.write(plain_text + "\n")
                else:
                    output_file.write("-1\n")

        elif option == 3:  # chosen ciphertext
            decryption_key1 = int(opts[1])
            decryption_key2 = int(opts[2])

            cipher_text = re.sub("[^A-Z]", "", opts[3].upper())

            plain_text = Cryptanalysis.chosen_ciphertext(
                cipher_text,
                decryption_key1,
                decryption_key2,
            )

            # output_file.write(plain_text + "\n")

        elif option == 4:  # chosen plaintext
            encryption_key1 = int(opts[1])
            encryption_key2 = int(opts[2])

            cipher_text = re.sub("[^A-Z]", "", opts[3].upper())

            plain_text = Cryptanalysis.chosen_plaintext(
                cipher_text, encryption_key1, encryption_key2
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
