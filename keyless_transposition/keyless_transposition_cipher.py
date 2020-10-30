#!/usr/bin/env sage

import math

BOGUS_CHARACTER = "Z"


class KeylessTransposition:
    """Keyless Transposition Class

    This will encrypt any alphabetic string (white spaces are also allowed) in case sensitive form using Keyless
    Transposition algorithm.

    Example :
        Plain Text : MEETMEATTHEPARK
        Columns : 4

        Cipher Text : MMTAEEHREAEKTTP
    """

    def encrypt(self, plain_text, num_cols):
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

        count = 0
        for i in range(col):
            for j in range(row):
                if count >= plain_text_len:
                    break
                result += matrix[j][i]
                count += 1
        return result

    def decrypt(self, cipher_text, num_cols):
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

        bogus_count = plain_text.count(BOGUS_CHARACTER)

        if bogus_count > 0:
            return plain_text[:-bogus_count]

        return plain_text


if __name__ == "__main__":
    """
    Driver function


    Program Input/Output Specifications :

    * The INPUT file must be named `input.txt` and each line would be the test cases in the format :
                                        A,B,C
        - A is the integer denoting Encryption or Decryption. 1 is for Encryption. 2 is for Decryption.
        - B denotes the number of columns used for the column by column encryption.
        - C denotes the message to encrypt or decrypt.

    * The OUTPUT file will contain the results of all the test cases seperated by newlines in the order
    given in the input file. The name of the output file will be `output.txt`. Incase of invalid input, the
    output of that particular testcase will be -1.
    """
    keyless_transp = KeylessTransposition()

    input_file = open("input.txt", "r")
    output_file = open("output.txt", "w")

    for line in input_file:
        (option, cols, msg) = [x.strip() for x in line.split(",")]
        option = int(option)
        num_cols = int(cols)

        if option == 1:  # encryption
            plain_text = msg
            cipher_text = keyless_transp.encrypt(plain_text, num_cols)
            output_file.write(cipher_text + "\n")

        elif option == 2:  # decryption
            cipher_text = msg
            plain_text = keyless_transp.decrypt(cipher_text, num_cols)
            output_file.write(plain_text + "\n")
