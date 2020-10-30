#!/usr/bin/env sage

from classical_ciphers.utils.ngram_score import ngram_score
from classical_ciphers.utils.helper import repeat
import re
import os
from itertools import permutations


DIR_PATH = os.path.dirname(os.path.realpath(__file__))
CWD_PATH = os.getcwd()

qgram = ngram_score(CWD_PATH + "/classical_ciphers/utils/quadgrams.txt")
trigram = ngram_score(CWD_PATH + "/classical_ciphers/utils/bigrams.txt")


class VignereCipher:
    """Vignere Cipher Class

    This will encrypt any alphabetic string in UPPERCASE form using Vignere
    Cipher algorithm. Non-alphabetical characters are NOT allowed.

    Example :
        Plain Text : SHEISLISTENING
        key : PASCAL

        Cipher Text : HHWKSWXSLGNTCG
    """

    @staticmethod
    def generate_key(string_template, key):
        """This function is used to repeat the key in cyclic manner to match
        the plain text or cipher text length"""
        key = list(key)
        if len(string_template) == len(key):
            return key
        else:
            for i in range(len(string_template) - len(key)):
                key.append(key[i % len(key)])
        return "".join(key)

    @staticmethod
    def encrypt(plain_text, key):
        """Returns the cipher text encrypted with `key` using Vignere Cipher Algoirthm

        Args:
            plain_text (str): Message to be encrypted. It should contain only
            alphabets.
            key (str): Key to encrypt the plaintext.

        Returns:
            result (str): Encrypted message or the cipher text
        """
        result = ""
        key = VignereCipher.generate_key(plain_text, key)
        for i in range(len(plain_text)):
            x = (ord(plain_text[i]) + ord(key[i])) % 26
            x += ord("A")
            result += chr(x)
        return result

    @staticmethod
    def decrypt(cipher_text, key):
        """Returns the decrypted_seq plain text of the given cipher text encrypted
        with `key`

        Args:
            cipher_text (str): Cipher text or the encrypted text to be
            decrypted_seq. It should contain only alphabets.
            key (str): Key to encrypt the plaintext.

        Returns:
            result (str): Plain text or the original unencrypted message
        """
        result = ""
        key = VignereCipher.generate_key(cipher_text, key)
        for i in range(len(cipher_text)):
            x = (ord(cipher_text[i]) - ord(key[i])) % 26
            x += ord("A")
            result += chr(x)
        return result


class Cryptanalysis:
    @staticmethod
    def chosen_ciphertext(cipher_text, decryption_key):
        """We have access to decryption algorithm in this technique"""
        fullkey = ""
        cipher_text = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
        plain_text = VignereCipher.decrypt(cipher_text, encryption_key)
        for i in range(len(cipher_text)):
            fullkey += chr(
                (ord(cipher_text[i]) - ord(plain_text[i])) % 26 + 65
            )
        key = re.findall(r"(.+)\1", fullkey)[0]
        return key

    @staticmethod
    def chosen_plaintext(cipher_text, encryption_key):
        """We have access to encryption algorithm in this technique"""
        fullkey = ""
        plain_text = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
        cipher_text = VignereCipher.encrypt(plain_text, encryption_key)
        for i in range(len(plain_text)):
            fullkey += chr(
                (ord(cipher_text[i]) - ord(plain_text[i])) % 26 + 65
            )
        key = re.findall(r"(.+)\1", fullkey)[0]
        return key

    @staticmethod
    def known_plaintext(prev_plain_text, prev_cipher_text, cipher_text):
        fullkey = ""
        for i in range(len(plain_text)):
            fullkey += chr(
                (ord(cipher_text[i]) - ord(plain_text[i])) % 26 + 65
            )

        key = re.findall(r"(.+)\1", fullkey)[0]

        return VignereCipher.decrypt(cipher_text, key)

    @staticmethod
    def ciphertext_only(ciphertext):

        N = 100  # Top 100 is passed on in each generation
        possible_keys_of_each_len = []
        for KLEN in range(3, 20):  # MAX Key Length : 20
            # Starting score calculated from trigrams
            print("Trying keys of length " + str(KLEN))
            fit_scores = []

            for i in permutations("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 3):
                key = "".join(i) + "A" * (KLEN - len(i))

                decrypted_seq = VignereCipher.decrypt(cipher_text, key)
                score = 0
                # Total score is sum of score of each block encrypted using
                # key
                for j in range(0, len(cipher_text), KLEN):
                    score += trigram.score(decrypted_seq[j : j + 3])
                fit_scores.append((score, "".join(i)))

            fit_scores = sorted(fit_scores, reverse=True)[:N]

            new_fit_scores = []

            """
            Iteratively add each character to each of 100 possible keys and
            test fitness
            Select top 100 from result and repeat
            """
            for i in range(0, KLEN - 3):
                for score, partial_key in fit_scores:
                    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                        fullkey = (
                            partial_key
                            + c
                            + "A" * (KLEN - len(partial_key) - 1)
                        )
                        decrypted_seq = VignereCipher.decrypt(
                            cipher_text, fullkey
                        )
                        score = 0
                        """
                        Total score is taken as sum of score of each block
                        encrypted using key
                        We use only substring of len(key) to score because
                        the remaining is padding in our current key
                        """
                        for j in range(0, len(cipher_text), KLEN):
                            score += qgram.score(
                                decrypted_seq[j : j + len(partial_key) + 1]
                            )
                        new_fit_scores.append((score, partial_key + c))

                fit_scores = sorted(new_fit_scores, reverse=True)[:N]
                new_fit_scores = []

            bestkey = fit_scores[0][1]
            bestscore = qgram.score(
                VignereCipher.decrypt(cipher_text, bestkey)
            )

            # Calculate score using top 100 found keys on entire cipher text

            for score, tempkey in fit_scores:
                decrypted_seq = VignereCipher.decrypt(cipher_text, tempkey)
                final_score = qgram.score(decrypted_seq)
                if final_score > bestscore:
                    bestkey = tempkey
                    bestscore = final_score
            possible_keys_of_each_len.append((bestscore, bestkey))

        max_key = max(possible_keys_of_each_len)[1]
        return VignereCipher.decrypt(cipher_text, max_key)


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

            plain_text = re.sub("[^A-Z]", "", opts[2].upper())
            key = opts[1]

            cipher_text = VignereCipher.encrypt(plain_text, key)

            output_file.write(cipher_text + "\n")

        elif option == 2:  # decryption

            cipher_text = re.sub("[^A-Z]", "", opts[2].upper())
            key = opts[1]

            plain_text = VignereCipher.decrypt(cipher_text, key)

            output_file.write(plain_text + "\n")

        elif option == 3:  # chosen ciphertext

            decryption_key = opts[1]

            cipher_text = re.sub(
                "[^A-Z]", "", opts[2].upper()
            )  # remove special characters and convert to UPPERCASE

            plain_text = Cryptanalysis.chosen_ciphertext(
                cipher_text, decryption_key
            )

            output_file.write(plain_text + "\n")

        elif option == 4:  # chosen plaintext

            encryption_key = opts[1]

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