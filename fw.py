import sys
import os

# Array to store rules as dictionaries
RULES = []

def setRules(filename):
    success = True
    # check if filename is a file
    if os.path.isfile(filename):
        try:
            # open the file to read
            with open(filename, 'r') as rfile:
                count = 0
                # for each line in the file
                for line in rfile:
                    count += 1
                    lineContent = line.split()
                    # if the rule is valid
                    if validRule(lineContent):
                        # turn it into a dictionary
                        direction = lineContent[0]
                        action = lineContent[1]
                        ip = lineContent[2]
                        port = lineContent[3].split(",")

                        # check established
                        if port == lineContent[-1]:
                            established = 0
                        else:
                            established = 1

                        rule = { 'direction': direction,
                                 'action': action,
                                 'ip': ip
                                 'port': port
                                 'established': established
                                 'ruleNum': count
                        }

                        # add it to the list of rules
                        global RULES
                        RULES.append(rule)
                    else:
                        print("Error: Invalid rule has been found")
                        success = False
            rfile.close()
            return


if __name__ == "__main__":

    if len(sys.argv) == 2:
        filename = sys.argv[1]

        if not setRules(filename):
            print("Error: Unable to process rules from configuration file")
            sys.exit()
        





    else:
        print("Error: Incorrect Number of Arguments")
        print("Usage: fw.py <configuration file>")
