#!/usr/bin/env sage

from ngram_score import ngram_score
import re
import os
import random


DIR_PATH = os.path.dirname(os.path.realpath(__file__))
CWD_PATH = os.getcwd()

MAXKEY = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


fitness = ngram_score(DIR_PATH + "/quadgrams.txt")


class SubstitutionCipher:
    """Substitution Cipher Class

    This will encrypt any alphabetic string (white spaces are also allowed) in
    case sensitive form using Monoalphabetic Substitution algorithm. Incase
    any special characters are inputted, it will not encrypt it and it will be
    included in the cipher text (incase of encrypting) and plain text (incase
    of decrypting).

    Example :
        Plain Text : The quick brown fox jumps over the lazy dog
        Plain Alphabets : abcdefghijklmnopqrstuvwxyz
        Cipher Alphabets : yhkqgvxfoluapwmtzecjdbsnri

        Cipher Text : Jfg zdoku hemsw vmn ldptc mbge jfg ayir qmx
    """

    @staticmethod
    def decrypt(cipher_text, key):
        """Returns the decrypted plain text of the given cipher text encrypted
        with `plain_alphabets` and `cipher_alphabets`

        Args:
            cipher_text (str): Cipher text or the encrypted text to be
            decrypted. It should contain only alphabets. Non-alphabetical
            characters will not be decrypted.

            key (list(str)): Used for 1-1 mapping from cipher text to
            plain text

        Returns:
            result (str): Plain text or the original unencrypted message
        """
        result = ""
        for i in range(len(cipher_text)):
            idx = key.index(cipher_text[i])
            result += MAXKEY[idx]

        return result

    @staticmethod
    def encrypt(plain_text, key):
        """Returns the cipher text encrypted with `plain_alphabets` and
        `cipher_alphabets` using Monoalphabetic Substitution Cipher Algorithm.

        Args:
            plain_text ([type]): Message to be encrypted. It should contain
            only alphabets. Non-alphabetical characters will not be encrypted.

            key (list(str)): Used for 1-1 mapping from cipher text to
            plain text

        Returns:
            result (str): Encrypted message or the cipher text
        """
        result = ""
        for i in range(len(plain_text)):
            idx = MAXKEY.index(plain_text[i])
            result += key[idx]

        return result


class Cryptanalysis:
    @staticmethod
    def chosen_ciphertext(cipher_text, decryption_key):
        """We have access to decryption algorithm in this technique"""

        plain_text = "-1"
        chosen_cipher = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        key_lst = [0] * 26

        for i in chosen_cipher:
            plain_chr = SubstitutionCipher.decrypt(i, decryption_key)
            key_idx = ord(plain_chr) - ord("A")
            key_lst[key_idx] = i

        plain_text = SubstitutionCipher.decrypt(cipher_text, key_lst)
        return plain_text

    @staticmethod
    def chosen_plaintext(cipher_text, encryption_key):
        """We have access to encryption algorithm in this technique"""

        key_lst = []
        plain_text = "-1"

        chosen_plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for i in chosen_plain:
            key_lst += SubstitutionCipher.encrypt(i, encryption_key)

        plain_text = SubstitutionCipher.decrypt(cipher_text, key_lst)
        return plain_text

    @staticmethod
    def known_plaintext(prev_plain_text, prev_cipher_text, cipher_text):
        key = [""] * 26
        plain_text = "-1"

        for i in range(len(prev_plain_text)):
            key_idx = ord(prev_plain_text[i]) - ord("A")
            key[key_idx] = prev_cipher_text[i]

        unfound_chars = sorted(
            list(set(MAXKEY) - set(key)), key=lambda x: ord(x)
        )

        unused_idx = list(filter(lambda idx: key[idx] == "", range(len(key))))

        # print(key)
        # print(unused_idx)
        # print(unfound_chars)

        """ Fill key with unused chararcters """
        for i, j in zip(unused_idx, unfound_chars):
            key[i] = j

        """ If all characters are found """
        if len(unfound_chars) == 26 or len(unfound_chars) == 25:
            return key

        parent_key = key[:]
        decrypted = SubstitutionCipher.decrypt(
            cipher_text, "".join(parent_key)
        )
        max_score = fitness.score(decrypted)
        count = 0
        while count < 1000:
            child_key = parent_key[:]
            a_ind, b_ind = (
                random.randint(0, len(unused_idx) - 1),
                random.randint(0, len(unused_idx) - 1),
            )
            a, b = unused_idx[a_ind], unused_idx[b_ind]
            child_key[a], child_key[b] = child_key[b], child_key[a]

            decrypted = SubstitutionCipher.decrypt(
                cipher_text, "".join(child_key)
            )
            score = fitness.score(decrypted)
            if score > max_score:
                max_score = score
                parent_key = child_key  # Set new key as parent
                count = 0
            count += 1

        maxkey = "".join(parent_key)
        plain_text = SubstitutionCipher.decrypt(cipher_text, maxkey)
        return plain_text

    @staticmethod
    def ciphertext_only(ciphertext):
        """
        Cryptanalysis using Hill Climbing technique.

        Reference :
        http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/

        Since normal brute force is slow, we try to speed up the brute force
        using Heuristic Search Algorithm such as Hill Climbing.

        """
        maxkey = MAXKEY
        maxscore = -99e9
        plain_text = "-1"

        parentscore, parentkey = maxscore, maxkey[:]
        i = 0
        while i < 100:  # Considering only 100 Iterations
            i = i + 1
            random.shuffle(parentkey)
            deciphered = SubstitutionCipher.decrypt(cipher_text, parentkey)
            parentscore = fitness.score(deciphered)
            count = 0
            while count < 1000:
                a = random.randint(0, 25)
                b = random.randint(0, 25)
                child = parentkey[:]
                # swap two characters in the child
                child[a], child[b] = child[b], child[a]
                deciphered = SubstitutionCipher.decrypt(cipher_text, child)
                score = fitness.score(deciphered)
                # if the child was better, replace the parent with it
                if score > parentscore:
                    parentscore = score
                    parentkey = child[:]
                    count = 0
                count = count + 1
            # keep track of best score seen so far
            if parentscore > maxscore:
                maxscore, maxkey = parentscore, parentkey[:]
                print("\nbest score so far:", maxscore, "on iteration", i)
                print("    best key: " + "".join(maxkey))
                print(
                    "    plaintext: "
                    + SubstitutionCipher.decrypt(cipher_text, maxkey)
                )
        plain_text = SubstitutionCipher.decrypt(cipher_text, maxkey)
        return plain_text


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
            key = re.sub("[^A-Z]", "", opts[1].upper())
            key = list(key)

            cipher_text = SubstitutionCipher.encrypt(plain_text, key)
            output_file.write(cipher_text + "\n")

        elif option == 2:  # decryption
            cipher_text = re.sub("[^A-Z]", "", opts[2].upper())
            key = re.sub("[^A-Z]", "", opts[1].upper())
            key = list(key)

            plain_text = SubstitutionCipher.decrypt(cipher_text, key)
            output_file.write(plain_text + "\n")

        elif option == 3:  # chosen ciphertext

            decryption_key = re.sub("[^A-Z]", "", opts[1].upper())

            cipher_text = re.sub(
                "[^A-Z]", "", opts[2].upper()
            )  # remove special characters and convert to UPPERCASE

            plain_text = Cryptanalysis.chosen_ciphertext(
                cipher_text, decryption_key
            )

            output_file.write(plain_text + "\n")

        elif option == 4:  # chosen plaintext

            encryption_key = re.sub("[^A-Z]", "", opts[1].upper())

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