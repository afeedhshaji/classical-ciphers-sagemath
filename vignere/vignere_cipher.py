#!/usr/bin/env sage

from classical_ciphers.utils.ngram_score import ngram_score
from classical_ciphers.utils.helper import repeat, regex_repeat
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
        chosen_cipher = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
        decr_chosen_cipher = VignereCipher.decrypt(
            chosen_cipher, decryption_key
        )
        for i in range(len(chosen_cipher)):
            fullkey += chr(
                (ord(chosen_cipher[i]) - ord(decr_chosen_cipher[i])) % 26 + 65
            )
        print(fullkey)
        key = repeat(fullkey)
        return VignereCipher.decrypt(cipher_text, key)

    @staticmethod
    def chosen_plaintext(cipher_text, encryption_key):
        """We have access to encryption algorithm in this technique"""
        fullkey = ""
        chosen_plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
        encr_chosen_plain = VignereCipher.encrypt(chosen_plain, encryption_key)
        for i in range(len(chosen_plain)):
            fullkey += chr(
                (ord(encr_chosen_plain[i]) - ord(chosen_plain[i])) % 26 + 65
            )
        print(fullkey)
        key = repeat(fullkey)
        return VignereCipher.decrypt(cipher_text, key)

    @staticmethod
    def known_plaintext(prev_plain_text, prev_cipher_text, cipher_text):
        fullkey = ""
        for i in range(len(prev_plain_text)):
            fullkey += chr(
                (ord(prev_cipher_text[i]) - ord(prev_plain_text[i])) % 26 + 65
            )

        key = repeat(fullkey)

        return VignereCipher.decrypt(cipher_text, key)

    @staticmethod
    def ciphertext_only(ciphertext):
        """
        Cryptanalysis using Hill Climbing technique.

        Reference :
        http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/

        Since normal brute force is slow, we try to speed up the brute force
        using Heuristic Search Algorithm such as Hill Climbing.

        """
        keys = []
        for KLEN in range(3, 20):  # MAX Key Length : 20
            print("KLEN " + str(KLEN))
            scores = []

            for i in permutations("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 3):
                key = "".join(i) + "A" * (KLEN - len(i))

                decrypted_seq = VignereCipher.decrypt(cipher_text, key)
                score = 0

                for j in range(0, len(cipher_text), KLEN):
                    score += trigram.score(decrypted_seq[j : j + 3])
                scores.append((score, "".join(i)))

            scores = sorted(scores, reverse=True)[:100]

            new_scores = []

            for i in range(0, KLEN - 3):
                for score, partial_key in scores:
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

                        for j in range(0, len(cipher_text), KLEN):
                            score += qgram.score(
                                decrypted_seq[j : j + len(partial_key) + 1]
                            )
                        new_scores.append((score, partial_key + c))

                scores = sorted(new_scores, reverse=True)[:100]
                new_scores = []

            bestkey = scores[0][1]
            bestscore = qgram.score(
                VignereCipher.decrypt(cipher_text, bestkey)
            )

            for i, j in scores:
                decrypted_seq = VignereCipher.decrypt(cipher_text, j)
                score = qgram.score(decrypted_seq)
                if score > bestscore:
                    bestkey = j
                    bestscore = score
            keys.append((bestscore, bestkey))

        max_key = max(keys)[1]
        return VignereCipher.decrypt(cipher_text, max_key)


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