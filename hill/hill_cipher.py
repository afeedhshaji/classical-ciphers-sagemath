from sage.all import Matrix, IntegerModRing
import numpy as np
import math


class HillCipher:
    """Hill Cipher Class

    This will encrypt/decrypt any alphabetic string using Hill Cipher Algorithm. No spaces in input are allowed. The
    plain text or the cipher text should be striclty UPPERCASE.

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

    def encrypt(self, plain_text, key):
        """Returns the encrypted cipher text of the given plain text encrypted with `key`

        Args:
            plain_text (str): Unencrypted or Plain Text
            key (matrix): Key used for encrypting the plain text. Should be a square matrix and inverse should exist.

        Returns:
            result (str): Encrypted message
        """

        key_matrix = np.array(key)

        key_rows = key_matrix.shape[0]
        key_columns = key_matrix.shape[1]

        if key_rows != key_columns:
            output_file.write("-1\n")

        if np.linalg.det(key_matrix) == 0:
            output_file.write("-1\n")

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

    def decrypt(self, cipher_text, key):
        """Returns the decrypted plain text of the given cipher text encrypted with `key`

        Args:
            cipher_text (str): Cipher text or the encrypted text to be decrypted.
            key (matrix): Key used for encrypting the plain text. Should be a square matrix and inverse should exist.

        Returns:
            result (str): Plain Text or Unencrypted text.
        """

        key = np.array(key)

        key_rows = key.shape[0]
        key_columns = key.shape[1]

        cipher_text_array = []
        for i in range(len(cipher_text)):
            cipher_text_array.append(ord(cipher_text[i]) - ord("A"))

        n = len(cipher_text_array)

        # filling with bogus characters
        if n % key_rows != 0:
            for i in range(0, n):
                cipher_text_array.append(cipher_text_array[i])
                if len(cipher_text_array) % key_rows == 0:
                    break

        cipher_text_array = np.array(cipher_text_array)
        cipher_text_array_len = len(cipher_text_array)

        cipher_text_array.resize(int(cipher_text_array_len / key_rows), key_rows)

        cipher_text_matrix = cipher_text_array

        inverse_key = Matrix(IntegerModRing(26), key).inverse()
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


if __name__ == "__main__":

    hill_cipher = HillCipher()

    input_file = open("input.txt", "r")
    output_file = open("output.txt", "w")

    for line in input_file:
        (option, key, msg) = [x.strip() for x in line.split(",")]
        option = int(option)
        x = len(key)

        if option == 1:  # encryption
            if math.sqrt(x) ** 2 == x:
                plain_text = msg
                keymat = HillCipher.getKeyMatrix(key)
                cipher_text = hill_cipher.encrypt(plain_text, keymat)
                output_file.write(cipher_text + "\n")

            else:
                output_file.write("-1\n")

        elif option == 2:  # decryption
            if math.sqrt(x) ** 2 == x:
                cipher_text = msg
                keymat = HillCipher.getKeyMatrix(key)
                plain_text = hill_cipher.decrypt(cipher_text, keymat)
                output_file.write(plain_text + "\n")
            else:
                output_file.write("-1\n")