import sys
import os

# Array to store rules as dictionaries
RULES = []

def validPacket(packet):
    validP = True
    packetContent = packet.split()
    if len(packetContent) != 4:
        print("Error: Malformed packet detected - Incorrect Fields")
        print("Valid Packet: <direction> <ip> <port> [flag]")
        return False

    pDirection = packetContent[0]
    pIP = packetContent[1]
    pPort = packetContent[2]
    pFlag = packetContent[3]

    if pDirection not in ("in", "out"):
        print("Error: Malformed packet detected - Invalid Direction")
        print("Allowed values for <direction>: \"in\" and \"out\" ")
        validP = False

    if pIP.split(".") != 4:
        print("Error: Malformed packet detected - IP must be in notation: a.b.c.d")
        validP = False
    
    if pPort not in range(0, 65535):
        print("Error: Malformed packet detected - Port is not in range (0-65535)")
        validP = False
    
    if pFlag not in (0,1):
        print("Error: Malformed packet detected - Invalid flag value")
        print("<flag> specifies whether the packet is part of a new (0) session or established (1) session.")
        validP = False

    return validP
    
    
def handlePacket(packet):

    # can the packet to processed
    canProcess = True
    # there is currently no rule that can apply to the packet
    noRule = True
    # Compare against rules here
    for rule in RULES:
        
        if packet['direction'] != rule['direction']:
            canProcess = False
        
        if rule['ip'] == ["*"]:
            pass
        elif not compareIP(packet['ip'], rule['ip']):
            canProcess = False
        
        if rule['ports'] == ["*"]:
            pass
        elif packet['port'] not in rule['ports']:
            canProcess = False
        
        # can process if either both are the same or rule['established] == 0
        if packet['flag'] != rule['flag'] AND rule['flag'] != 0:
            canProcess = False
            
        if canProcess == True:
            output = rule['action'] + "(" + str(rule['ruleNum']) + ") " + packet['direction'] + " " + packet['ip'] + " " + packet['port'] + " " + packet['flag']
            print(output)
            # A rule has been matched
            noRule = False
            break
        else:
            # reset canProcess flag for next rule
            canProcess = True

    # If no rule can be found default action is drop()
    if noRule:
        output = "drop() " + packet['direction'] + " " + packet['ip'] + " " + packet['port'] + " " + packet['flag']
        print(output)

    return

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
                print("Error: Malformed rule detected on line " + count + " - Port is not in range (0-65535)")
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
                        direction = lineContent[0]
                        action = lineContent[1]
                        ip = lineContent[2]
                        port = lineContent[3]
                        ports = port.split(",")

                        # check established (if ports is the last field established is false)
                        if port == rule[-1]:
                            established = 0
                        else:
                            established = 1

                        rule = { 'direction': direction,
                                 'action': action,
                                 'ip': ip
                                 'ports': ports
                                 'flag': established
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
            validator = validPacket(line)

            if validator == True:
                # put packet into a dictionary
                pContent = line.split()

                pDirection = pContent[0]
                pIP = pContent[1]
                pPort = pContent[2]
                pFlag = pContent[3]

                packet = { 'direction': pDirection,
                           'ip': pIP,
                           'port': pPort,
                           'flag': pFlag
                }

                # check with rules list
                handlePacket(packet)
            else:
                print("Error: Packet could not be processed")
                sys.exit()

    else:
        print("Error: Incorrect Number of Arguments")
        print("Usage: fw.py <configuration file>")
        sys.exit()
