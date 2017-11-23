import sys
import os
import traceback
import math

# Array to store rules as dictionaries
RULES = []

def compareIPold(packetIP, ruleIP, num):
    #print("ENTERED COMPARE IP " + str(num))
    # Convert to octet
    pktIP = []
    #ruleIP = []

    # Get ranges
    #pIP = packetIP.split(".")
    #rIP = ruleIP.split(".")    
    pRange = packetIP.split(".")[3]
    rRange = ruleIP.split(".")[3] 
    pRange = pRange.split("/")[0]
    rRange = rRange.split("/")[0] 

    # Range to Octet
    if pRange[0] != pRange[-1]:
        pMask = binaryMask(pRange[0])
    else:
        pMask = [255,255,255,255]
    pktIP = packetIP.split("/")[0]
    pkt = pktIP, pMask

    if rRange[0] != rRange[-1]:
        rMask = binaryMask(rRange[0])
    else:
        rMask = [255,255,255,255]   
    ruleIP = ruleIP.split("/")[0] 
    rule = ruleIP, rMask 


    # Compare ip,mask 
    if pkt == rule:
        #print("TRUE: ruleIP: " + str(rule) + " packetIP: " + str(pkt))
        return True
    else:
        #print("FALSE: ruleIP: " + str(rule) + " packetIP: " + str(pkt))
        return False


def ipMask(ipAddress):
    #print(ipAddress)
    # Get octets
    ipFinal = []
    ip = ipAddress.split("/")[0]
    #print("IP BITCH")
    ip = ip.split(".")
    ipRange = ipAddress.split(".")[3].split("/")
    #print("IPRANGE" + str(ipRange))

    for octets in ip:
        ipFinal.append(octets) 

    # Get range octets
    x = ipRange[-1]
    #print("IPRANGE" + str(x))
    #ipMask = toOctet(x)
    
    if ipRange[-1] != ipRange[0]:
        ipMask = toOctet(ipRange[-1])
    else:
        ipMask = [255,255,255,255]


    return [ipFinal, ipMask]

def toOctet(range):
    finalMask = []
    rangeMask = int(range)

    # Get octets from range
    while rangeMask > 0:
        rangeMask = rangeMask - 8
        if rangeMask <= 0:
            finalOctet = abs(rangeMask)

            lastMask = 0
            while finalOctet >= 0:
                lastMask = lastMask + math.pow(2, 8 - finalOctet)
                finalOctet = finalOctet - 1
            finalMask.append(lastMask)
        else:
            finalMask.append(255)


    # If got less than 4 octets, append 0s
    if len(finalMask) < 4:
        while len(finalMask) < 4:
            finalMask.append(0)
    return finalMask


    # Range to Octet
    if pRange[0] != pRange[-1]:
        pMask = binaryMask(pRange[0])
    else:
        pMask = [255,255,255,255]
    pktIP = packetIP.split("/")[0]
    pkt = pktIP, pMask

    if rRange[0] != rRange[-1]:
        rMask = binaryMask(rRange[0])
    else:
        rMask = [255,255,255,255]   
    ruleIP = ruleIP.split("/")[0] 


def compareIPfuck(rIP, pIP):
    
    # Get IPs and Masks

    rules = ipMask(rIP)
    packets = ipMask(pIP)
    ruleIP = rules[0]
    ruleMask = rules[1]
    packetIP = packets[0]
    packetMask = packets[1]

    # Compare with lists
    checkPacket = []
    checkRules = []

    for i in range(0, len(ruleIP)):
        checkPacket.append(int(packetIP[i]) & int(ruleMask[i]))
        checkRules.append(int(ruleIP[i]) & int(ruleMask[i]))

    if checkPacket == checkRules:
        #print(str(checkPacket) + " " + str(checkRules))
        return True, str(checkPacket), str(checkRules)
    else:
        #print(str(checkPacket) + " " + str(checkRules))
        return False, str(checkPacket), str(checkRules)

def compareIP(rIP, pIP):
    ruleIP = toBinary(rIP)
    packetIP = toBinary(pIP)
    if ruleIP == packetIP:
        return True
    else:
        return False

def toBinary(ipAddress):
    # Taken from https://stackoverflow.com/questions/3465099/ip-address-conversion-using-python
    ip = str(ipAddress)
    return ''.join([bin(256 + int(ip))[3:] for ip in '123.123.123.123'.split('.')])

def validPacket(packet):
    validP = True
    packetContent = packet.split()
    # Each packet will have exactly 4 fields
    if len(packetContent) != 4:
        print("Error: Malformed packet detected - Incorrect Fields")
        print("Valid Packet: <direction> <ip> <port> <flag>")
        return False

    pDirection = str(packetContent[0])
    pIP = str(packetContent[1])
    pPort = int(packetContent[2])
    pFlag = int(packetContent[3])

    if pDirection not in ("in", "out"):
        print("Error: Malformed packet detected - Invalid Direction")
        print("Allowed values for <direction>: \"in\" and \"out\" ")
        validP = False

    if len(pIP.split(".")) != 4:
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

def flagCheck(packet, rule):
    if rule == 0:
        return True
    elif rule == 1 and packet == 1:
        return True 
    elif rule == 1 and packet == 0:
        return False
    
    
def handlePacket(packet):

    # can the packet to proces sed
    canProcess = True
    # there is currently no rule that can apply to the packet
    noRule = True
    # Compare against rules here
    for rule in RULES:       
        print("RULENUM: " + str(rule['ruleNum']))
        if packet['direction'] != rule['direction']:
            canProcess = False

        if rule['ip'] == "*":
            pass

        elif not compareIP(packet['ip'],rule['ip']):
            canProcess = False

        """
        elif rule['ip'] != '*':
            compareResult = compareIP(packet['ip'],rule['ip'])
            boolean = compareResult[0]
            packett = compareResult[1]
            rulesss = compareResult[2]
            if boolean == False:
                print("CompareIP: " + str(rule['ruleNum']) + " " + str(rule['ip']) + " " + str(packet['ip']))
                print("CompareIP: " + str(rule['ruleNum']) + "\n" + str(packett) + "\n" + str(rulesss))
                canProcess = False
               """ 
        if rule['ports'] == "*" or '*' in rule['ports']:
            pass
        elif packet['port'] not in rule['ports']:
            print(str(rule['ruleNum']) + " " + str(packet['port']) + " " + str(rule['ports']))
            canProcess = False
        
        # can process if either both are the same or rule['established] == 0
        if packet['flag'] != rule['flag'] and rule['flag'] != 0:
            canProcess = False

            
        if canProcess == True:
            debugMessage = "\n".join([
                "RULENUM: " + str(rule['ruleNum']),
                "rAction: " + str(rule['action']),
                "----------------------------------",
                "pDir: " + str(packet['direction']),
                "rDir: " + str(rule['direction']),
                "----------------------------------",
                "pIP: " + str(packet['ip']),
                "rIP: " + str(rule['ip']),
                "----------------------------------",
                "pPort: " + str(packet['port']),
                "rPort: " + str(rule['ports']),
                "----------------------------------",
                "pFlag: " + str(packet['flag']),
                "rFlag: " + str(rule['flag']),
                "----------------------------------"
                ])
            #print(debugMessage)
            output = rule['action'] + "(" + str(rule['ruleNum']) + ") " + packet['direction'] + " " + packet['ip'] + " " + packet['port'] + " " + str(packet['flag'])
            
            # Compare the checks from compareIP()
            #print("Packet check: " + str(packett))
            #rint("Packet check: " + str(rulesss))

            print(output)
            # A rule has been matched
            noRule = False
            break
        else:
            # reset canProcess flag for next rule
            canProcess = True


    # If no rule can be found default action is drop()
    debugMessage = "\n".join([
        "RULENUM: " + str(rule['ruleNum']),
        "rAction: " + str(rule['action']),
        "----------------------------------",
        "pDir: " + str(packet['direction']),
        "rDir: " + str(rule['direction']),
        "----------------------------------",
        "pIP: " + str(packet['ip']),
        "rIP: " + str(rule['ip']),
        "----------------------------------",
        "pPort: " + str(packet['port']),
        "rPort: " + str(rule['ports']),
        "----------------------------------",
        "pFlag: " + str(packet['flag']),
        "rFlag: " + str(rule['flag']),
        "----------------------------------"
        ])
    if noRule:
        output = "drop() " + packet['direction'] + " " + packet['ip'] + " " + packet['port'] + " " + str(packet['flag'])
        print(output)
        #print(debugMessage)

    return

def validRule(rule, count):
    validR = True

    # minimum fields is 4, maximum fields is 5
    if len(rule) < 4 or len(rule) > 5:
        print("Error: Malformed rule detected on line " + str(count) + " - Incorrect Fields")
        print("Valid Rule: <direction> <action> <ip> <port> [flag]")
        return False

    #split contents
    direction = str(rule[0])
    action = str(rule[1])
    ip = str(rule[2])
    port = str(rule[3])
    ports = port.split(",")

    # check established (if port is the last field established is false)
    if port == rule[-1]:
        established = False
    else:
        established = True

    # check valid direction
    if direction not in ("in", "out"):
        print("Error: Malformed rule detected on line " + str(count) + " - Invalid Direction")
        print("Allowed values for <direction>: \"in\" and \"out\" ")
        validR = False

    # check valid action
    if action not in ("accept", "drop", "reject"):
        print("Error: Malformed rule detected on line " + str(count) + " - Invalid Action")
        print("Allowed values for <action>: \"accept\", \"drop\", and \"reject\" ")
        validR = False
    
    # check valid IP notation
    if ip == "*":
        pass
    else:
        octets = ip.split(".")
        cidr = octets[3].split("/")
        if len(octets) != 4 or len(cidr) != 2:
            print("Error: Malformed rule detected on line " + str(count) + " - IP must be in CIDR notation: a.b.c.d/xx")
            validR = False
    
    # check valid ports
    for p in ports:
        if p == "*":
            pass
        else:
            p = int(p)
            if p not in range(0, 65535):
                print("Error: Malformed rule detected on line " + str(count) + " - Port is not in range (0-65535)")
                validR = False

    # check if [flag] is actually 'established'
    if established == True:
        if rule[-1] != "established":
            print("Error: Malformed rule detected on line " + str(count) + " - Allowed value for [flag]: \"established\"")
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
                        direction = str(lineContent[0])
                        action = str(lineContent[1])
                        ip = str(lineContent[2])
                        port = str(lineContent[3])
                        ports = port.split(",")

                        # check established (if ports is the last field established is false)
                        if port == lineContent[-1]:
                            established = 0
                        else:
                            established = 1

                        rule = { 'direction': direction,
                                 'action': action,
                                 'ip': ip,
                                 'ports': ports,
                                 'flag': established,
                                 'ruleNum': count
                        }

                        # add it to the list of rules
                        RULES.append(rule)
                    else:
                        # if an invalid rule is found, report errors and stop the program
                        success = False
                        break
            rfile.close()
        except:
            tb = traceback.format_exc()
            print (tb)
            print("Error: Could not open " + filename)
            return False
    
    return success


if __name__ == "__main__":

    if len(sys.argv) == 2:
        filename = sys.argv[1]

        # process configuration file
        if not setRules(filename):
            print("Error: Unable to process rules from configuration file")
            sys.exit()

        packetCounter = 1
        for line in sys.stdin:
            # validate packet
            validator = validPacket(line)

            if validator == True:
                # put packet into a dictionary
                pContent = line.split()

                pDirection = str(pContent[0])
                pIP = str(pContent[1])
                pPort = str(pContent[2])
                pFlag = int(pContent[3])

                packet = { 'direction': pDirection,
                           'ip': pIP,
                           'port': pPort,
                           'flag': pFlag
                }

                # check with rules list
                print("\n\n" + str(packetCounter) + ": ", end ="")
                packetCounter = packetCounter + 1
                handlePacket(packet)
            else:
                print("Error: Packet could not be processed")
                sys.exit()

    else:
        print("Error: Incorrect Number of Arguments")
        print("Usage: fw.py <configuration file>")
        sys.exit()
