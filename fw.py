import sys
import os

# Array to store rules as dictionaries
RULES = []

def validPacket(packet):
    validP = True
    if len(packet) != 4:
        print("Error: Malformed packet detected - Incorrect Fields")
        print("Valid Packet: <direction> <ip> <port> [flag]")
        return False
    

    
def handlePacket(packet):

def validRule(rule, count):
    validR = True

    # minimum fields is 4, maximum fields is 5
    if len(rule) < 4 or len(rule) > 5:
        print("Error: Malformed rule detected on line " + count + " - Incorrect Fields")
        print("Valid Rule: <direction> <action> <ip> <port> [flag]")
        return False

    #split contents
    direction = rule[0]
    action = rule[1]
    ip = rule[2]
    port = rule[3]
    ports = port.split(",")

    # check established (if ports is the last field established is false)
    if port == rule[-1]:
        established = False
    else:
        established = True

    # check valid direction
    if direction not in ("in", "out"):
        print("Error: Malformed rule detected on line " + count + " - Invalid Direction")
        print("Allowed values for <direction>: \"in\" and \"out\" ")
        validR = False

    # check valid action
    if action not in ("accept", "drop", "reject"):
        print("Error: Malformed rule detected on line " + count + " - Invalid Action")
        print("Allowed values for <action>: \"accept\", \"drop\", and \"reject\" ")
        validR = False
    
    # check valid IP notation
    if ip == "*":
        pass
    else:
        octets = ip.split(".")
        cidr = octets[3].split("/")
        if len(octets) != 4 or cidr != 2:
            print("Error: Malformed rule detected on line " + count + " - IP must be in CIDR notation: a.b.c.d/xx")
            validR = False
    
    # check valid ports
    for p in ports:
        if p == "*":
            pass
        else:
            if p not in range(0, 65535):
                print("Error: Malformed rule detected on line " + count + " - A port is not in range (0-65535)")
                validR = False

    # check if [flag] is established
    if established == True:
        if rule[-1] != "established":
            print("Error: Malformed rule detected on line " + count + " - Allowed value for [flag]: \"established\"")
            validR = False
            
    return validR


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
                    if validRule(lineContent, count):
                        # turn it into a dictionary

                        #split contents
                        direction = rule[0]
                        action = rule[1]
                        ip = rule[2]
                        port = rule[3]
                        ports = port.split(",")

                        # check established (if ports is the last field established is false)
                        if port == rule[-1]:
                            established = False
                        else:
                            established = True

                        rule = { 'direction': direction,
                                 'action': action,
                                 'ip': ip
                                 'ports': ports
                                 'established': established
                                 'ruleNum': count
                        }

                        # add it to the list of rules
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
            # validate packet
            
            # check with rules list

        





    else:
        print("Error: Incorrect Number of Arguments")
        print("Usage: fw.py <configuration file>")
