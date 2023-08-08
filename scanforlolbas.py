from pandas import *
import argparse
import os
import string

def parse_file(fp,lollist):
    try:
        fn =os.path.basename(fp)
        with open(fp, "r") as f:
            file_data = f.readlines()
        for x in file_data:
            x = x.lower()
            for y in lollist:
                y = y.lower()
                if y in x:
                    left,sep,right = x.partition(y)
                    ALPHA = string.ascii_letters
                    x = x.rstrip()
                    x = x.replace(',',';')
                    list = []
                    if not (left[1:]).endswith(tuple(ALPHA)):
                        list.append(y)
                        list.append(fn)
                        list.append(x)
                    if list:
                        list = (','.join(list))
                        list = (" ".join(list.split()))
                        print(list)
    except UnicodeDecodeError:
        pass # non-text data

def main():
    # Set arguments for input and output
    parser = argparse.ArgumentParser(description='Search text files for lolbas strings. https://lolbas-project.github.io/api/lolbas.csv')
    parser.add_argument("-p", "--path", help = "Path to input file or directory to scan", required=True)
    parser.add_argument("-l", "--lolbascsv", help = "Path to lolbas.csv", required=True)

    args = parser.parse_args()
    input_path = args.path
    lolbas_path = args.lolbascsv

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
            fp = os.path.join(input_path, dir_item)
            if os.path.isfile(fp):
                parse_file(fp,lollist)

    #Enumerate and verify file in input string, then send to parser
    elif os.path.isfile(input_path):
        fp = input_path
        parse_file(fp,lollist)
    else:
        print("invalid path!!")

if __name__ == "__main__":
    main()
