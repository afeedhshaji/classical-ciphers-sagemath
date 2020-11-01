import re


def repeat(s):
    """
    Finding continuous repeated patterns in a string using Prefix array
    technique.
    """
    prefix_array = []
    for i in range(len(s)):
        prefix_array.append(s[:i])
    # stop at 1st element to avoid checking for the ' ' char
    for i in prefix_array[:1:-1]:
        if s.count(i) > 1:
            # find where the next repetition starts
            offset = s[len(i) :].find(i)
            return s[: len(i) + offset]
            break
    return s


def regex_repeat(string):
    """
    Finding continuous repeated patterns in a string using RegEx.
    """
    return re.findall(r"(.+)\1", string)[0]
