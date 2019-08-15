from c3 import get_key_singlechar_xor


def percent_char(string):

    string = string.lower()

    count = 0

    for byte in string:

        if byte >= 97 and byte <= 122:

            count += 1

    return count / len(string)


def detect_enc_strings(strings):

    scores = []

    for string in strings:

        result = get_key_singlechar_xor(string)

        # if percent_char(result[2]) >= 0.5:              # if needed, keep a lower bound on the percentage of alphabets in the text
        
        scores.append(result)

    scores.sort(key = lambda x: x[1], reverse = True)

    return scores


def main():

    strings = [bytes(line.strip(), 'utf-8') for line in open('c4.txt')]

    scores = detect_enc_strings(strings)

    assert(b'Now that the party is jumping\n' in scores[0])

    print("Best score:\n")

    print(scores[0])


if __name__ == '__main__':
    main()