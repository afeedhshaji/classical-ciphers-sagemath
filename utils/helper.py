def repeat(string):
    for x in range(1, len(string)):
        substring = string[:x]

        if (
            substring * (len(string) // len(substring))
            + (substring[: len(string) % len(substring)])
            == string
        ):
            print(substring)
            return "break"

    print(string)