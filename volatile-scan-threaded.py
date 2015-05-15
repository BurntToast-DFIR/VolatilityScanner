#! /usr/bin/env python

from optparse import OptionParser
import os.path
from os import walk
import subprocess
import threading
from ThreadPool import ThreadPool

# Declare global variables

VOLATILITY_MODULES = ["connscan", "sockscan", "psxview", "pstree" ]
MAX_THREADS = 3
VOLATILITY_COMMAND = "volatility"

# Set up options

parser = OptionParser(usage="%prog [options]",version="1.0")
parser.add_option("-f","--file", dest="inputFile", help="Single file to scan", metavar="FILE")
parser.add_option("-d","--directory", dest="inputDir", help="Directory to can", metavar="IN_DIR")
parser.add_option("-r", "--recursive", action="store_true", dest="recurse", default=False, help="Recurse through subdirectories")
parser.add_option("-o", "--output", dest="outputDir", help="Output Directory", metavar="OUT_DIR")
parser.add_option("-p", "--profile", dest="profile", help="Voalitility Ptofile", metavar="PROFILE")

(options, args) = parser.parse_args()

# Check that we aren't trying to parse both a single file and a directory
if options.inputFile and options.inputDir:
	parser.error("options -f and -d are mutually exclusive.")
if not (options.inputFile or options.inputDir):
    parser.error("No input defined.  Try -h or --help for usage info")

# Check that all the file system options are correct
if options.inputFile and not os.path.exists(options.inputFile):
    parser.error("Cannot find the specified input file")
if options.inputDir and not os.path.exists(options.inputDir):
    parser.error("Cannot find the specified input directory")
if options.outputDir and not os.path.exists(options.outputDir):
    parser.error("Cannot find the specified output directory")

class FileScanner:
    def __init__(self, fileName, outputDir, modules, profile):
        self.file = fileName
        self.dir = outputDir
        self.modules = modules
        self.profile = profile

    def scan(self):
        pool = ThreadPool(MAX_THREADS)
        for mod in self.modules:
            pool.add_task(self.runmodule,  mod)
        pool.wait_completion()
        
    def runmodule(self, module):
        command = [VOLATILITY_COMMAND]
        basename = os.path.splitext(os.path.basename(self.file))[0]
        outputFile = os.path.join(self.dir ,  basename + "_" + module + ".txt")
        args = ["--file=" + self.file ,  "--profile=" + self.profile,   "--output-file=" +outputFile + " ",   module]
        command.extend(args)
        print("Attempting to run: " + ' '.join(command))
        subprocess.call(' '.join(command),  shell=True)
        
class DirScanner:
        def __init__(self, dirName, outputDir, modules, profile):
            self.dir = dirName
            self.outDir = outputDir
            self.modules = modules
            self.profile = profile
            
        def scan(self):
            for root,  dirs,  files in walk(self.dir):
                for name in files:
                    self.__scanfile(os.path.join(root, name))
                        
        def __scanfile(self, file):
            scanner = FileScanner(file,  self.outDir,  self.modules,  self.profile)
            scanner.scan()
            
if __name__ == "__main__":
    scanner = DirScanner("/root/memdumps/",  "/root/out/",  VOLATILITY_MODULES,  "Win2003SP2x86")
    scanner.scan()
