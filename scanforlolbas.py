from pandas import *
import argparse
import os
import string

def parse_file(file_to_parse,lollist):
    try:
        with open(file_to_parse, "r") as f:
            file_data = f.readlines()
        for x in file_data:
            for y in lollist:
                if y in x:
                    left,sep,right = x.partition(y)
                    ALPHA = string.ascii_letters
                    if not (left[1:]).endswith(tuple(ALPHA)):
                        print(file_to_parse)
                        print(x)
                        print(y)
    except UnicodeDecodeError:
        pass # non-text data

def main():
    # Set arguments for input and output
    parser = argparse.ArgumentParser(description='Search text files for lolbas strings. https://lolbas-project.github.io/api/lolbas.csv')
    parser.add_argument("-p", "--path", help = "Path to input file or directory to scan", required=True)
    parser.add_argument("-l", "--lolbas", help = "Path to lolbas.csv", required=True)

    args = parser.parse_args()
    input_path = args.path
    lolbas_path = args.lolbas

    args = parser.parse_args()

    lolbas_file = read_csv(lolbas_path)
    lollist = []
    filenames = lolbas_file['Filename'].tolist()
    for f in filenames:
        if f not in lollist:
            lollist.append(f)

    #Enumerate and verify files in directory path, then send to parser
    if (os.path.isdir(input_path)):
        for dir_item in os.listdir(input_path):
            file_to_parse = os.path.join(input_path, dir_item)
            if os.path.isfile(file_to_parse):
                parse_file(file_to_parse,lollist)

    #Enumerate and verify file in input string, then send to parser
    elif os.path.isfile(input_path):
        file_to_parse = input_path
        parse_file(file_to_parse,lollist)
    else:
        print("invalid path!!") 

if __name__ == "__main__":
    main()
