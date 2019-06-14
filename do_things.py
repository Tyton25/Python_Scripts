"""
This script takes up to to command line arguments
"""

import filecmp
import re
import argparse

PHONE_NUMBER_REGEX = r'\d{3}-\d{3}-\d{4}'


class DoThings:
    def __init__(self, text_file=None, comp_files=None):
        self.text_file = text_file
        self.comp_files = comp_files

    def run(self):
        if self.text_file is not None:
            self.get_phone_numbers()
        if self.comp_files is not None:
            self.compare_files()

    def get_phone_numbers(self):
        phone_num = re.compile(PHONE_NUMBER_REGEX, re.IGNORECASE)
        input_file = self.text_file[0]
        output_file = self.text_file[1]
        with open(input_file, 'r') as f:
            lines = f.readlines()
        with open(output_file, 'a') as out_file:
            for line in lines:
                if phone_num.match(line):
                    out_file.write(line)
        print("Done extracting phone numbers from input text file.")

    def compare_files(self):
        file_cmp_value = filecmp.cmp(self.comp_files[0], self.comp_files[1])
        print(file_cmp_value)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--text_file",
                        nargs=2,
                        help="Input text file")
    parser.add_argument("-c", "--comp_files",
                        nargs=2,
                        help="Enter two files to compare")
    args = parser.parse_args()

    if args.text_file:
        assert len(args.text_file) == 2, "Please enter input file name and output file name."
        txt_file = args.text_file
    else:
        txt_file = None
    if args.comp_files:
        assert len(args.comp_files) == 2, "Please enter two files."
        cmp_files = args.comp_files
    else:
        cmp_files = None

    return txt_file, cmp_files


if __name__ == '__main__':
    text_file, comp_files = get_args()
    do_things = DoThings(text_file=text_file, comp_files=comp_files)
    do_things.run()
