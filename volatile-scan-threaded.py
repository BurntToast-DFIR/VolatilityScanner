#! /usr/bin/env python

from optparse import OptionParser
import os.path
from os import walk,  devnull
import subprocess
import threading
from ThreadPool import ThreadPool
import re

# Declare global variables

MODULES = ['apihooks', 'cmdscan', 'connections', 'connscan', 'consoles', 'deskscan', 'devicetree', 'dlllist', 'driverirp', \
'driverscan', 'eventhooks', 'filescan', 'getsids', 'handles', 'hivelist', 'hivescan', 'idt', 'imageinfo', 'kdbgscan', 'ldrmodules', \
'malfind', 'memmap', 'modscan', 'modules', 'mutantscan', 'netscan', 'pslist', 'psscan', 'pstree', 'psxview', 'sessions', 'shellbags', \
'shimcache', 'sockets', 'sockscan', 'ssdt', 'svcscan', 'thrdscan', 'unloadedmodules', 'userassist', 'vadinfo', 'vadtree', 'vadwalk', 'wndscan']

MAX_THREADS = 3
VOLATILITY_COMMAND = 'volatility'
LAST_PROFILE = ''

# Set up options

parser = OptionParser(usage='%prog [options]',version='1.0')
parser.add_option('-f','--file', dest='inputFile', help='Single file to scan', metavar='FILE')
parser.add_option('-d','--directory', dest='inputDir', help='Directory to scan', metavar='IN_DIR')
parser.add_option('-o', '--output', dest='outputDir', help='Output directory', metavar='OUT_DIR')
parser.add_option('-p', '--profile', dest='profile', help='Voalitility profile', metavar='PROFILE')
parser.add_option('-s', '--search', dest='search', help='Search term (regex)', metavar='SEARCH_STRING')
parser.add_option('-m',  '--modules-list',  dest='moduleList',  help='Specify modules to run (file or comma separated list)',  metavar='LIST_or_FILE')
parser.add_option('-t',  '--max-threads',  dest='maxThreads',  help='Max number of threads available',  metavar='NUM_THREADS')

(options, args) = parser.parse_args()

# Check that we aren't trying to parse both a single file and a directory
if options.inputFile and options.inputDir:
	parser.error('options -f and -d are mutually exclusive.')
if not (options.inputFile or options.inputDir):
    parser.error('No input defined.  Try -h or --help for usage info')

# Check that all the file system options are correct
if options.inputFile and not os.path.exists(options.inputFile):
    parser.error('Cannot find the specified input file')
if options.inputDir and not os.path.exists(options.inputDir):
    parser.error('Cannot find the specified input directory')
if options.outputDir and not os.path.exists(options.outputDir):
    parser.error('Cannot find the specified output directory')
    
# Check if default modules are in use.
if options.moduleList:
    if os.path.exists(options.moduleList):
        custom_modules = []
        file = open(options.moduleList)
        for line in file.readlines():
            custom_modules.extend(line.split(','))
        file.close()
        MODULES = []
        for module in custom_modules:
            if module.strip <> '':
                MODULES.append(module.strip())
    else:
        MODULES = options.moduleList.split(',')

if options.maxThreads:
   try:
      MAX_THREADS = int(options.maxThreads)
      if MAX_THREADS < 1 or MAX_THREADS > 100:
        parser.error("Max threads should be specified as an integer between 1 and 100")
   except:
        parser.error("Max threads should be specified as an integer between 1 and 100")
       
    
        
class FileScanner:
    def __init__(self, fileName, outputDir, modules, profile):
        self.file = fileName
        self.dir = outputDir
        self.modules = modules
        self.profile = profile
        
        # Check to see if a profile has been specified, if not then run the imageinfo plugin and allow user to select an option
        global LAST_PROFILE
        if profile == None and LAST_PROFILE <> '':
            self.profile = LAST_PROFILE
        elif profile == None and LAST_PROFILE == '':
            print('Attempting to determine profile:')
            self.runmodule('imageinfo')
            basename = os.path.splitext(os.path.basename(self.file))[0]
            infoFileName = os.path.join(self.dir ,  basename + '_' + 'imageinfo.txt')
            with open(infoFileName) as f:
                for line in f:
                    if 'Suggested Profile' in line:
                        suggestedProfiles = line[33:].split(', ')
                        profileCount = 1 
                        print('The following profiles have been found: ' + ', '.join(suggestedProfiles) )
                        for p in suggestedProfiles:
                            p = p.strip()
                            print(str(profileCount) + ': ' + p)
                            profileCount = profileCount + 1 
                        selected = 0
                        while selected < 1 or selected > profileCount:
                            print('Enter a number to select profile [1]:')
                            try:
                                selected = int(raw_input())
                            except:
                                selected = 0
                        self.profile = suggestedProfiles[selected - 1].strip()
                        LAST_PROFILE = self.profile
            
        # if still no profile specified then exit gracefully
        if self.profile == None:
            print("Unable to determine profile.  Exiting.")
            exit()
            
                            

    def scan(self):
        pool = ThreadPool(MAX_THREADS)
        for mod in self.modules:
            pool.add_task(self.runmodule,  mod)
        pool.wait_completion()
        
    def runmodule(self, module):
        command = [VOLATILITY_COMMAND]
        basename = os.path.splitext(os.path.basename(self.file))[0]
        outputFile = os.path.join(self.dir ,  basename + '_' + module + '.txt')
        if self.profile == None:
            args = ['--file=' + self.file ,  '--output-file=' +outputFile + ' ',   module]
        else:
            args = ['--file=' + self.file ,  '--profile=' + self.profile,   '--output-file=' +outputFile + ' ',   module]
        command.extend(args)
        print('Running ' + module +' on ' + self.file)
        try:
            DEVNULL = open(devnull,  'wb')
            subprocess.call(' '.join(command),  shell=True,  stderr=DEVNULL)
            print('Finished running '+ module +' on ' + self.file)
        except:
            print('An error occured running module ' + module)
            e = sys.exc_info()[0]
            write_to_page( 'Error: %s' % e )
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
            
if __name__ == '__main__':
    
    if options.inputDir:
        scanner = DirScanner(options.inputDir,  options.outputDir,  MODULES,  options.profile)
        scanner.scan()
    else:
        scanner = FileScanner(options.inputFile,  options.outputDir,  MODULES,  options.profile)
        scanner.scan()
    
    #Search all results if required
    if options.search:
        if options.search == 'IP':
            pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        else:
            pattern = re.compile(options.search)
        ofile = open (os.path.join(options.outputDir, 'SearchHits.txt'), 'w+')
        for root,  dirs,  files in walk(options.outputDir):
            for name in files:
                if name <> 'SearchHits.txt':
                    ifile = open(os.path.join(root, name), 'r')
                    line = 0
                    for text in ifile.readlines():
                        line = line + 1
                        for match in pattern.finditer(text):
                            print (name + '[' + str(line) + ']: ' + match.group())
                            ofile.write (name + ',' + str(line) +',' + match.group() + ',' + text + '\n')
                    ifile.close()
        ofile.close()
        
