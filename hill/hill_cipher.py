from sage.all import Matrix, IntegerModRing
from classical_ciphers.utils.ngram_score import ngram_score
import os
import numpy as np
import math
import re

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
CWD_PATH = os.getcwd()

fitness = ngram_score(CWD_PATH + "/classical_ciphers/utils/quadgrams.txt")


class HillCipher:
    """Hill Cipher Class

    This will encrypt/decrypt any alphabetic string using Hill Cipher
    Algorithm. No spaces in input are allowed. The plain text or the cipher
    text should be striclty UPPERCASE.

    Example :
        Plain Text : CODEISREADY
        Key : JHLNEHFGCVOJDXVI

        Cipher Text : OHKNIHGHFISS
    """

    @staticmethod
    def getKeyMatrix(key):
        dim = int(math.sqrt(len(key)))
        keyMatrix = [[0] * dim for i in range(dim)]
        k = 0
        for i in range(dim):
            for j in range(dim):
                keyMatrix[i][j] = ord(key[k]) % 65
                k += 1
        return keyMatrix

    @staticmethod
    def encrypt(plain_text, key):
        """Returns the encrypted cipher text of the given plain text encrypted
        with `key`

        Args:
            plain_text (str): Unencrypted or Plain Text

            key (matrix): Key used for encrypting the plain text. Should be a
            square matrix and inverse should exist.

        Returns:
            result (str): Encrypted message
        """

        key_matrix = np.array(key)

        key_rows = key_matrix.shape[0]
        key_columns = key_matrix.shape[1]

        if key_rows != key_columns:  # Not square matrix
            return "-1"

        try:
            inverse_key = Matrix(IntegerModRing(26), key).inverse()
        except ZeroDivisionError:
            return "-1"

        result = ""
        plain_text_array = []

        for i in range(len(plain_text)):
            if plain_text[i] != " ":
                idx = ord(plain_text[i]) - ord("A")
                plain_text_array.append(idx)

        n = len(plain_text_array)

        if n % key_rows != 0:
            for i in range(0, n):
                plain_text_array.append(25)
                if len(plain_text_array) % key_rows == 0:
                    break

        plain_text_array = np.array(plain_text_array)
        plain_text_array_len = len(plain_text_array)
        plain_text_array.resize(int(plain_text_array_len / key_rows), key_rows)
        plain_text_matrix = plain_text_array

        result = np.matmul(plain_text_matrix, key)
        result = np.remainder(result, 26)

        result_array = result.flatten()

        result = ""
        for i in range(0, len(result_array)):
            result += chr(result_array[i] + ord("A"))

        return result

    @staticmethod
    def decrypt(cipher_text, key):
        """Returns the decrypted plain text of the given cipher text encrypted
        with `key`

        Args:
            cipher_text (str): Cipher text or the encrypted text to be
            decrypted.

            key (matrix): Key used for encrypting the plain text. Should be a
            square matrix and inverse should exist.

        Returns:
            result (str): Plain Text or Unencrypted text.
        """

        key = np.array(key)

        key_rows = key.shape[0]
        key_columns = key.shape[1]

        if key_rows != key_columns:  # Not square matrix
            return "-1"

        cipher_text_array = []
        for i in range(len(cipher_text)):
            cipher_text_array.append(ord(cipher_text[i]) - ord("A"))

        cipher_text_array = np.array(cipher_text_array)
        cipher_text_array_len = len(cipher_text_array)

        cipher_text_array.resize(
            int(cipher_text_array_len / key_rows), key_rows
        )

        cipher_text_matrix = cipher_text_array

        try:
            inverse_key = Matrix(IntegerModRing(26), key).inverse()
        except ZeroDivisionError:
            return "-1"

        inverse_key = np.array(inverse_key)
        inverse_key = inverse_key.astype(float)

        decryption = np.matmul(cipher_text_matrix, inverse_key)
        decryption = np.remainder(decryption, 26).flatten()

        result = ""
        for i in range(0, len(decryption)):
            letter_num = int(decryption[i]) + ord("A")
            letter = chr(letter_num)
            result = result + letter

        return result


class Cryptanalysis:
    @staticmethod
    def chosen_ciphertext(cipher_text, decryption_key):
        """We have access to decryption algorithm in this technique"""
        plain_text = "-1"
        for dim in range(2, 11):  # key_dim : 2*2 to 11*11
            """
            Chosen Cipher is an identity matrix to get K_inv directly.

            Building the identity matrix :
            [["B" "A"]          [1 0]
            ["A" "B"]]          [0 1]
            """

            """ Filling with 0 """
            chosen_cipher_mat = ["A"] * (dim ** 2)

            """ FIlling diagnol elems with 1 """
            for j in range(dim):
                chosen_cipher_mat[dim * j + j] = "B"

            """
            To find out the inverse of the key matrix
            """
            chosen_cipher = "".join(chosen_cipher_mat)
            key_inv = HillCipher.decrypt(chosen_cipher, decryption_key)

            if key_inv != "-1":

                key_matrix_inv = HillCipher.getKeyMatrix(key_inv)

                """ K = mod_inv(K_inv)"""
                try:
                    key_matrix = Matrix(
                        IntegerModRing(26), key_matrix_inv
                    ).inverse()

                except ZeroDivisionError:
                    continue

                """
                Convert sagemath matrix to normal python list type matrix.
                """
                li = list(i for j in key_matrix for i in j)

                key_matrix = [[0] * dim for i in range(dim)]
                k = 0
                for i in range(dim):
                    for j in range(dim):
                        key_matrix[i][j] = li[k]
                        k += 1

                """ 
                TODO : Cipher text may not be divisble by the key dim. So
                splice the cipher text till the largest mutliple of dim.
                """
                chosen_cipher = cipher_text[: i ** 2]

                exp_plain_text = HillCipher.decrypt(chosen_cipher, key_matrix)
                orig_plain_text = HillCipher.decrypt(
                    chosen_cipher, decryption_key
                )
                if exp_plain_text == orig_plain_text:
                    break

        plain_text = HillCipher.decrypt(cipher_text, key_matrix)
        return plain_text

    @staticmethod
    def chosen_plaintext(cipher_text, encryption_key):
        """We have access to encryption algorithm in this technique"""
        plain_text = "-1"
        for dim in range(2, 11):  # key_dim : 2*2 to 11*11
            """
            Chosen Cipher is an identity matrix to get K_inv directly.

            Building the identity matrix :
            [["B" "A"]          [1 0]
            ["A" "B"]]          [0 1]
            """

            """ Filling with 0 """
            chosen_plain_mat = ["A"] * (dim ** 2)

            """ FIlling diagnol elems with 1 """
            for j in range(dim):
                chosen_plain_mat[dim * j + j] = "B"

            """
            To find out the the key matrix : I.K = K
            """
            chosen_plain = "".join(chosen_plain_mat)
            key = HillCipher.encrypt(chosen_plain, encryption_key)

            key_matrix = HillCipher.getKeyMatrix(key)

            """ 
            TODO : Cipher text may not be divisble by the key dim. So
            splice the cipher text till the largest mutliple of dim.
            """
            chosen_plain = (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
            )
            encr_chosen_plain = HillCipher.encrypt(
                chosen_plain, encryption_key
            )
            decr_chosen_plain = HillCipher.decrypt(
                encr_chosen_plain, key_matrix
            )
            if decr_chosen_plain == chosen_plain:
                break

        plain_text = HillCipher.decrypt(cipher_text, key_matrix)
        return plain_text

    @staticmethod
    def known_plaintext(prev_plain_text, prev_cipher_text, cipher_text):

        pass

    @staticmethod
    def ciphertext_only(ciphertext):
        """ Bruteforce keys. (Only 2x2 Hill CIphers) """
        maxscore = -99e9
        maxkey = None
        plain_text = "-1"

        for a in range(26):  # Loop 1
            for b in range(26):  # Loop 2
                for c in range(26):  # Loop 3
                    for d in range(26):  # Loop 4
                        key = np.matrix([[a, b], [c, d]])
                        if np.linalg.det(key) != 0:
                            decrypted = HillCipher.decrypt(cipher_text, key)
                            if decrypted != "-1":
                                fitness_score = fitness.score(decrypted)
                                if fitness_score > maxscore:
                                    maxscore = fitness.score(decrypted)
                                    maxkey = key
                                    print(
                                        "Score : %s, Key : %s"
                                        % (maxscore, maxkey)
                                    )
        plain_text = HillCipher.decrypt(cipher_text, maxkey)

        return plain_text


if __name__ == "__main__":

    input_file = open(DIR_PATH + "/input.txt", "r")
    output_file = open(DIR_PATH + "/output.txt", "w")

    for line in input_file:
        opts = [x.strip() for x in line.split(",")]
        option = int(opts[0])

        if option == 1:  # encryption
            key = re.sub("[^A-Z]", "", opts[1].upper())
            x = len(key)

            if math.sqrt(x) ** 2 == x:
                plain_text = re.sub("[^A-Z]", "", opts[2].upper())
                keymat = HillCipher.getKeyMatrix(key)

                cipher_text = HillCipher.encrypt(plain_text, keymat)

                output_file.write(cipher_text + "\n")

            else:
                output_file.write("-1\n")

        elif option == 2:  # decryption
            key = re.sub("[^A-Z]", "", opts[1].upper())
            x = len(key)

            if math.sqrt(x) ** 2 == x:
                cipher_text = re.sub("[^A-Z]", "", opts[2].upper())
                keymat = HillCipher.getKeyMatrix(key)

                plain_text = HillCipher.decrypt(cipher_text, keymat)

                output_file.write(plain_text + "\n")
            else:
                output_file.write("-1\n")

        elif option == 3:  # chosen ciphertext

            decryption_key = re.sub("[^A-Z]", "", opts[1].upper())
            dec_keymat = HillCipher.getKeyMatrix(decryption_key)

            cipher_text = re.sub(
                "[^A-Z]", "", opts[2].upper()
            )  # remove special characters and convert to UPPERCASE

            plain_text = Cryptanalysis.chosen_ciphertext(
                cipher_text, dec_keymat
            )

            output_file.write(plain_text + "\n")

        elif option == 4:  # chosen plaintext

            encryption_key = re.sub("[^A-Z]", "", opts[1].upper())
            enc_keymat = HillCipher.getKeyMatrix(encryption_key)

            cipher_text = re.sub("[^A-Z]", "", opts[2].upper())

            plain_text = Cryptanalysis.chosen_plaintext(
                cipher_text, enc_keymat
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
