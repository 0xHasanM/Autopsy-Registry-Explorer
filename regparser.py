from sys import argv
from os import listdir,path,getcwd
from json import loads
from csv import writer,reader
from Registry import Registry
def regparser(registry_hive, tempDir, modulepath):
    csv = open(tempDir + ".csv", "a", newline='')
    csv_write = writer(csv)
    bookmark_dir = modulepath + ".\\common\\"
    def key_parser(keyToParse):
        try:
            key = reg.open(keyToParse)
        except TypeError:
            key = keyToParse
        if bookmark_json["KeyPath"] in ["ControlSet001\\Control\\NetworkSetup2","ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy", \
                                        "ControlSet001\\Services\\Tcpip","Microsoft\\Windows NT\\CurrentVersion\\NetworkCards","Microsoft\\Windows NT\\CurrentVersion\\ProfileList", "Microsoft\\Windows Portable Devices", \
                                        "ControlSet001\\Enum\\USB", "Microsoft\\Windows\\CurrentVersion\\App Paths", "Microsoft\\Windows Defender", "Policies\\Microsoft\\Windows Defender", \
                                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32", \
                                        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"]:
            if key.subkeys_number() > 0 and key.values_number() == 0:
                for subkey in key.subkeys():
                    key_parser(subkey)
            elif key.subkeys_number()== 0 and key.values_number() > 0:
                for value in key.values():
                    if value.value_type() == 1 or value.value_type() == 2 or (value.value_type() == 4 and "_" not in value.name() and int(value.value()) > 1) or value.value_type() == 11 or value.value == "":
                        csv_data = [value.name(), value.value(), bookmark_json["LongDescription"], bookmark_json["KeyPath"].split('\\')[-1], key.path(), reg_hive, ]
                        try:
                            csv_write.writerow(csv_data)
                        except UnicodeEncodeError:
                            continue
            elif key.subkeys_number() > 0 and key.values_number() > 0:
                for subkey in key.subkeys():
                    key_parser(subkey)
                for value in key.values():
                    if value.value_type() == 1 or value.value_type() == 2 or (value.value_type() == 4 and "_" not in value.name() and int(value.value()) > 1) or value.value_type() == 11 or value.value == "":
                        csv_data = [value.name(), value.value(), bookmark_json["LongDescription"], bookmark_json["KeyPath"].split('\\')[-1], key.path(), reg_hive]
                        try:
                            csv_write.writerow(csv_data)
                        except UnicodeEncodeError:
                            continue
            elif key.subkeys_number() == 0 and key.values_number() == 0:
                pass
        else:
            for value in key.values():
                if value.value_type() == 1 or value.value_type() == 2 or (value.value_type() == 4 and "_" not in value.name() and int(value.value()) > 1) or value.value_type() == 11 or value.value == "":
                    csv_data = [value.name(), value.value(), bookmark_json["LongDescription"], bookmark_json["Category"], key.path(), reg_hive]
                    try:
                        csv_write.writerow(csv_data)
                    except UnicodeEncodeError:
                        continue
    for file in listdir(bookmark_dir):
        with open(bookmark_dir + file, 'r') as bookmark:
            bookmark_json = loads(bookmark.read())
        if bookmark_json["HiveType"].upper() in registry_hive:
            reg = Registry.Registry(registry_hive)
            reg_hive=registry_hive.split('\\')[-1]
            try:
                key_parser(bookmark_json["KeyPath"])
            except Registry.RegistryKeyNotFoundException:
                continue
if __name__ == '__main__':
    regparser(argv[1], argv[2], argv[3])
