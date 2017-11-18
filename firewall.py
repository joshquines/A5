import sys
import os

# Array to store rules as dictionaries
RULES = []

def setRules(filename):
    if os.path.isfile(filename):
        try:
            with open(filename, 'r') as rfile:
                for line in rfile:
                    lineContent = line.split()     
                    



if __name__ == "__main__":

    if len(sys.argv) == 2:
        filename = sys.argv[1]

        if not setRules(filename):
            print("Error: Unable to process rules from configuration file")
            sys.exit()
        





    else:
        print("Error: Incorrect Number of Arguments")
        print("Usage: fw.py <configuration file>")
