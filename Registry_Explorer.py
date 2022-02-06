import inspect
import os
import shutil
import ntpath
import subprocess
import csv
from com.williballenthin.rejistry import RegistryHiveFile
from com.williballenthin.rejistry import RegistryKey
from com.williballenthin.rejistry import RegistryParseException
from com.williballenthin.rejistry import RegistryValue
from java.io import File
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import Arrays
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import Blackboard
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.modules.interestingitems import FilesSetsManager
class RegistryExampleIngestModuleFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None
    moduleName = "RegistyExplorer Module"
    def getModuleDisplayName(self):
        return self.moduleName
    def getModuleDescription(self):
        return "Extract Keys To Look For Interesting Items"
    def getModuleVersionNumber(self):
        return "0.1 Beta"
    def hasIngestJobSettingsPanel(self):
        return False
    def isDataSourceIngestModuleFactory(self):
        return True
    def createDataSourceIngestModule(self, ingestOptions):
        return RegistryExampleIngestModule(self.settings)
class RegistryExampleIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(RegistryExampleIngestModuleFactory.moduleName)
    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
    def __init__(self, settings):
        self.context = None
    def startUp(self, context):
        self.context = context
        if PlatformUtil.isWindowsOS():
            self.regparser_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "regparser.exe")
            self.rla_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rla.exe")
            if not os.path.exists(self.regparser_exe) or not os.path.exists(self.rla_exe):
                raise IngestModuleException("EXE was not found in module folder")
        else:
            raise IngestModuleException("This module is for Windows OS only")
    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()
        filesToExtract = ("NTUSER.DAT", "SOFTWARE", "UsrClass.dat", "SAM", "SYSTEM")
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "RegistryExplorer")
        self.log(Level.INFO, "create Directory " + tempDir)
        try:
            os.mkdir(tempDir)
        except Exception as e:
            self.log(Level.INFO, "RegistryExplorer Directory already exists " + tempDir)
        skCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        softwarehive = ntuserhive = usrclasshive = samhive = systemhive = "na"
        for fileName in filesToExtract:
            files = fileManager.findFiles(dataSource, fileName)
            numFiles = len(files)
            for file in files:
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK
                if ((file.getName() == 'SOFTWARE') and (file.getSize() > 0)):
                    try:
                        ContentUtils.writeToFile(file, File(os.path.join(tempDir, file.getName())))
                        self.log(Level.INFO, "Begin Create"+os.path.join(tempDir, file.getName()))
                        software = file
                    except:
                        pass
                elif ((file.getName() == 'NTUSER.DAT') and (file.getSize() > 0)):
                    try:
                        fileName = str(file.getId()) + "-" + file.getName()
                        ContentUtils.writeToFile(file, File(os.path.join(tempDir, fileName)))
                        self.log(Level.INFO, "Begin Create"+os.path.join(tempDir, fileName))
                        ntuser = file
                    except:
                        pass
                elif ((file.getName() == 'UsrClass.dat') and (file.getSize() > 0)):
                    try:
                        fileName = str(file.getId()) + "-" + file.getName()
                        ContentUtils.writeToFile(file, File(os.path.join(tempDir, fileName)))
                        self.log(Level.INFO, "Begin Create"+os.path.join(tempDir, fileName))
                        usrclass = file
                    except:
                        pass
                elif ((file.getName() == 'SAM') and (file.getSize() > 0)):
                    try:
                        ContentUtils.writeToFile(file, File(os.path.join(tempDir, file.getName())))
                        self.log(Level.INFO, "Begin Create"+os.path.join(tempDir, file.getName()))
                        sam = file
                    except:
                        pass
                elif ((file.getName() == 'SYSTEM') and (file.getSize() > 0)):
                    try:
                        ContentUtils.writeToFile(file, File(os.path.join(tempDir, file.getName())))
                        self.log(Level.INFO, "Begin Create"+os.path.join(tempDir, file.getName()))
                        system = file
                    except:
                        pass
        for file in os.listdir(tempDir):
            software_hive = ntuser_hive = usrclass_hive = sam_hive = system_hive = "na"
            if 'software' in str(file).lower():
                self.log(Level.INFO, "Begin Create"+os.path.join(tempDir, file))
                software_hive = os.path.join(tempDir, file)
                subprocess.Popen([self.regparser_exe, ntuser_hive, software_hive, usrclass_hive, sam_hive, system_hive, tempDir, os.path.dirname(os.path.abspath(__file__))], stderr=subprocess.PIPE).communicate()[1]
            elif 'ntuser' in str(file).lower():
                ntuser_hive = os.path.join(tempDir, file)
                subprocess.Popen([self.regparser_exe, ntuser_hive, software_hive, usrclass_hive, sam_hive, system_hive, tempDir, os.path.dirname(os.path.abspath(__file__))], stderr=subprocess.PIPE).communicate()[1]
            elif 'usrclass' in str(file).lower():
                usrclass_hive = os.path.join(tempDir, file)
                subprocess.Popen([self.regparser_exe, ntuser_hive, software_hive, usrclass_hive, sam_hive, system_hive, tempDir, os.path.dirname(os.path.abspath(__file__))], stderr=subprocess.PIPE).communicate()[1]
            elif 'sam' in str(file).lower():
                sam_hive = os.path.join(tempDir, file)
                subprocess.Popen([self.regparser_exe, ntuser_hive, software_hive, usrclass_hive, sam_hive, system_hive, tempDir, os.path.dirname(os.path.abspath(__file__))], stderr=subprocess.PIPE).communicate()[1]
            elif 'system' in str(file).lower():
                system_hive = os.path.join(tempDir, file)
                subprocess.Popen([self.regparser_exe, ntuser_hive, software_hive, usrclass_hive, sam_hive, system_hive, tempDir, os.path.dirname(os.path.abspath(__file__))], stderr=subprocess.PIPE).communicate()[1]
        self.log(Level.INFO, "Begin Create New Artifacts")
        attributeIdRunKeyName = blackboard.getOrAddAttributeType("TSK_REG_KEY_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name")
        attributeIdRunKeyValue = blackboard.getOrAddAttributeType("TSK_REG_KEY_VALUE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Value")
        attributeIdRegKeyDesc = blackboard.getOrAddAttributeType("TSK_REG_KEY_DESC", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Description")
        attributeIdRegKeyCategory = blackboard.getOrAddAttributeType("TSK_REG_KEY_CATEGORY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Category")
        attributeIdRegKeyPath = blackboard.getOrAddAttributeType("TSK_REG_KEY_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PATH")		
        attributeIdRegHiveType = blackboard.getOrAddAttributeType("TSK_REG_HIVE_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "HiveType")
        moduleName = RegistryExampleIngestModuleFactory.moduleName
        data = []
        with open(tempDir+'.csv') as csv_file:
            keys = csv.reader(csv_file)
            for registryKey in keys:
                if ','.join(registryKey) in data:
                    continue
                else:
                    data += ','.join(registryKey)
                    try:
                        if "firewall" in registryKey[2]:
                            artType = blackboard.getOrAddArtifactType( "TSK_REGISTRY_KEYS_FIREWALL", "Windows Registry Keys (Firewall)")
                            registry = system
                            art = registry.newArtifact(artType.getTypeID())
                            art.addAttributes(((BlackboardAttribute(attributeIdRunKeyName, moduleName, registryKey[0])), \
                                               (BlackboardAttribute(attributeIdRunKeyValue, moduleName, registryKey[1])), \
                                               (BlackboardAttribute(attributeIdRegKeyDesc, moduleName, registryKey[2])), \
                                               (BlackboardAttribute(attributeIdRegKeyCategory, moduleName, registryKey[3])), \
                                               (BlackboardAttribute(attributeIdRegKeyPath, moduleName, registryKey[4])), \
                                               (BlackboardAttribute(attributeIdRegHiveType, moduleName, registryKey[5]))))
                            blackboard.postArtifact(art, moduleName)
                        elif "services" in registryKey[4].lower():
                            if registryKey[0] == "ImagePath":
                                artType = blackboard.getOrAddArtifactType( "TSK_REGISTRY_KEYS_SERVICES", "Windows Registry Keys (Services)")
                                registry = system
                                art = registry.newArtifact(artType.getTypeID())
                                art.addAttributes(((BlackboardAttribute(attributeIdRunKeyName, moduleName, registryKey[0])), \
                                                   (BlackboardAttribute(attributeIdRunKeyValue, moduleName, registryKey[1])), \
                                                   (BlackboardAttribute(attributeIdRegKeyDesc, moduleName, registryKey[2])), \
                                                   (BlackboardAttribute(attributeIdRegKeyCategory, moduleName, registryKey[3])), \
                                                   (BlackboardAttribute(attributeIdRegKeyPath, moduleName, registryKey[4])), \
                                                   (BlackboardAttribute(attributeIdRegHiveType, moduleName, registryKey[5]))))
                                blackboard.postArtifact(art, moduleName)
                            else:
                                continue
                        else:
                            artType = blackboard.getOrAddArtifactType( "TSK_REGISTRY_KEYS_"+registryKey[3], "Windows Registry Keys ("+registryKey[3]+")")
                            if "ntuser" in registryKey[5].lower():
                                registry = ntuser
                            elif "software" in registryKey[5].lower():
                                registry = software
                            elif "usrclass" in registryKey[5].lower():
                                registry = usrclass
                            elif "sam" in registryKey[5].lower():
                                registry = sam
                            elif "system" in registryKey[5].lower():
                                registry = system
                            art = registry.newArtifact(artType.getTypeID())
                            art.addAttributes(((BlackboardAttribute(attributeIdRunKeyName, moduleName, registryKey[0])), \
                                               (BlackboardAttribute(attributeIdRunKeyValue, moduleName, registryKey[1])), \
                                               (BlackboardAttribute(attributeIdRegKeyDesc, moduleName, registryKey[2])), \
                                               (BlackboardAttribute(attributeIdRegKeyCategory, moduleName, registryKey[3])), \
                                               (BlackboardAttribute(attributeIdRegKeyPath, moduleName, registryKey[4])), \
                                               (BlackboardAttribute(attributeIdRegHiveType, moduleName, registryKey[5]))))
                            blackboard.postArtifact(art, moduleName)
                    except Exception as e:
                        self.log(Level.INFO, str(e))
                        continue
        try:
            shutil.rmtree(tempDir + '\\..\\')
        except Exception as e:
            self.log(Level.INFO, "removal of directory tree failed " + tempDir)
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "RegistryExample", " RegistryExample Files Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)
        return IngestModule.ProcessResult.OK
