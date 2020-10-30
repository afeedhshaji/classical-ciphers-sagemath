#!/usr/bin/env sage


class SubstitutionCipher:
    """Substitution Cipher Class

    This will encrypt any alphabetic string (white spaces are also allowed) in case sensitive form using Monoalphabetic
    Substitution algorithm. Incase any special characters are inputted, it will not encrypt it and it will be included
    in the cipher text (incase of encrypting) and plain text (incase of decrypting).

    Example :
        Plain Text : The quick brown fox jumps over the lazy dog
        Plain Alphabets : abcdefghijklmnopqrstuvwxyz
        Cipher Alphabets : yhkqgvxfoluapwmtzecjdbsnri

        Cipher Text : Jfg zdoku hemsw vmn ldptc mbge jfg ayir qmx
    """

    def decrypt(self, cipher_text, plain_alphabets, cipher_alphabets):
        """Returns the decrypted plain text of the given cipher text encrypted with `plain_alphabets` and `cipher_alphabets`

        Args:
            cipher_text (str): Cipher text or the encrypted text to be decrypted. It should contain only alphabets.
            Non-alphabetical characters will not be decrypted.
            plain_alphabets (str): Used for 1-1 mapping from the plain text to cipher text
            cipher_alphabets (str): Used for 1-1 mapping from cipher text to plain text

        Returns:
            result (str): Plain text or the original unencrypted message
        """
        result = ""
        for i in range(len(cipher_text)):
            idx = cipher_alphabets.find(cipher_text[i].lower())
            if idx == -1:
                result += cipher_text[i]
            elif cipher_text[i].isupper():
                result += plain_alphabets[idx].upper()
            else:
                result += plain_alphabets[idx]
        return result

    def encrypt(self, plain_text, plain_alphabets, cipher_alphabets):
        """Returns the cipher text encrypted with `plain_alphabets` and `cipher_alphabets` using Monoalphabetic
        Substitution Cipher Algorithm.

        Args:
            plain_text ([type]): Message to be encrypted. It should contain only alphabets.
            Non-alphabetical characters will not be encrypted.
            plain_alphabets (str): Used for 1-1 mapping from the plain text to cipher text
            cipher_alphabets (str): Used for 1-1 mapping from cipher text to plain text

        Returns:
            result (str): Encrypted message or the cipher text
        """
        result = ""
        for i in range(len(plain_text)):
            idx = plain_alphabets.find(plain_text[i].lower())
            if idx == -1:
                result += plain_text[i]
            elif plain_text[i].isupper():
                result += cipher_alphabets[idx].upper()
            else:
                result += cipher_alphabets[idx]
        return result


if __name__ == "__main__":
    """
    Driver function


    Program Input/Output Specifications :

    * The INPUT file must be named `input.txt` and each line would be the test cases in the format :
                                        A,B,C,D
        - A is the integer denoting Encryption or Decryption. 1 is for Encryption. 2 is for Decryption.
        - B denotes the plain alphabets used to encrypt/decrypt.
        - C denotes the cipher alphabets used to encrypt/decrypt.
        - D denotes the message to encrypt or decrypt.

    * The OUTPUT file will contain the results of all the test cases seperated by newlines in the order
    given in the input file. The name of the output file will be `output.txt`. Incase of invalid input, the
    output of that particular testcase will be -1.
    """
    sub_cipher = SubstitutionCipher()

    input_file = open("input.txt", "r")
    output_file = open("output.txt", "w")

    for line in input_file:
        (option, plain_alphabets, cipher_alphabets, msg) = [
            x.strip() for x in line.split(",")
        ]
        option = int(option)
        if option == 1:  # encryption

            if len(plain_alphabets) == len(cipher_alphabets):
                plain_text = msg
                cipher_text = sub_cipher.encrypt(
                    plain_text, plain_alphabets, cipher_alphabets
                )
                output_file.write(cipher_text + "\n")
            else:
                output_file.write("-1\n")

        elif option == 2:  # decryption
            if len(plain_alphabets) == len(cipher_alphabets):
                cipher_text = msg
                plain_text = sub_cipher.decrypt(
                    cipher_text, plain_alphabets, cipher_alphabets
                )
                output_file.write(plain_text + "\n")
            else:
                output_file.write("-1\n")
