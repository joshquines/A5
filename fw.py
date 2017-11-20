import sys
import os

# Array to store rules as dictionaries
RULES = []

def validRule(rule, direction, action, ip, ports, established, count):
    valid = True

    # minimum fields is 4, maximum fields is 5
    if len(rule) < 4 or len(rule) > 5:
        print("Error: Malformed rule detected on line " + count + " - Incorrect Fields")
        print("Valid Rule: <direction> <action> <ip> <port> [flag]")
        return False

    # check valid direction
    if direction not in ("in", "out"):
        print("Error: Malformed rule detected on line " + count + " - Invalid Direction")
        print("Allowed values for <direction>: \"in\" and \"out\" ")
        valid = False

    # check valid action
    if action not in ("accept", "drop", "reject"):
        print("Error: Malformed rule detected on line " + count + " - Invalid Action")
        print("Allowed values for <action>: \"accept\", \"drop\", and \"reject\" ")
        valid = False
    
    # check valid IP notation
    if ip == "*":
        pass
    else:
        octets = ip.split(".")
        cidr = octets[3].split("/")
        if len(octets) != 4 or cidr != 2:
            print("Error: Malformed rule detected on line " + count + " - IP must be in CIDR notation: a.b.c.d/xx")
            valid = False
    
    # check valid ports
    for p in ports:
        if p == "*":
            pass
        else:
            if p not in range(0, 65535):
                print("Error: Malformed rule detected on line " + count + " - A port is not in range (0-65535)")
                valid = False

    # check if [flag] is established
    if established == True:
        if rule[-1] != "established":
            print("Error: Malformed rule detected on line " + count + " - Allowed value for [flag]: \"established\"")
            valid = False
            
    return valid


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

                    #split contents
                    direction = lineContent[0]
                    action = lineContent[1]
                    ip = lineContent[2]
                    port = lineContent[3]
                    ports = port.split(",")

                    # check established (if ports is the last field established is false)
                    if port == lineContent[-1]:
                        established = False
                    else:
                        established = True

                    # if the rule is valid
                    if validRule(lineContent, direction, action, ip, ports, established, count):
                        # turn it into a dictionary
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
                        success = False
            rfile.close()
            return
        except:
            print("Error: Could not open " + filename)
            return False
    
    return success


if __name__ == "__main__":

    if len(sys.argv) == 2:
        filename = sys.argv[1]

        if not setRules(filename):
            print("Error: Unable to process rules from configuration file")
            sys.exit()

        for line in sys.stdin:
            
        





    else:
        print("Error: Incorrect Number of Arguments")
        print("Usage: fw.py <configuration file>")
