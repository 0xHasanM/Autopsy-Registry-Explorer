from sys import argv
from os import listdir,path,getcwd
from json import loads
from csv import writer,reader
from Registry import Registry
def regparser(ntuserhive, softwarehive, usrclasshive, samhive, systemhive, tempDir, modulepath):
    csv = open(tempDir + ".csv", "a", newline='')
    csv_write = writer(csv)
    bookmark_dir = modulepath + ".\\common\\"
    for file in listdir(bookmark_dir):
        with open(bookmark_dir + file, 'r') as bookmark:
            bookmark_json = loads(bookmark.read())
        if bookmark_json["HiveType"].lower() == "ntuser":
            if ntuserhive == "na":
                continue
            else:
                reg = Registry.Registry(ntuserhive)
                reg_hive=ntuserhive.split('\\')[-1]
        elif bookmark_json["HiveType"].lower() == "software":
            if softwarehive == "na":
                continue
            else:
                reg = Registry.Registry(softwarehive)
                reg_hive=softwarehive.split('\\')[-1]
        elif bookmark_json["HiveType"].lower() == "usrclass":
            if usrclasshive == "na":
                continue
            else:
                reg = Registry.Registry(usrclasshive)
                reg_hive=usrclasshive.split('\\')[-1]
        elif bookmark_json["HiveType"].lower() == "sam":
            if samhive == "na":
                continue
            else:
                reg = Registry.Registry(samhive)
                reg_hive=samhive.split('\\')[-1]
        elif bookmark_json["HiveType"].lower() == "system":
            if systemhive == "na":
                continue
            else:
                reg = Registry.Registry(systemhive)
                reg_hive=systemhive.split('\\')[-1]
        else:
            continue
        try:
            key = reg.open(bookmark_json["KeyPath"])
            if bookmark_json["HiveType"].lower() != "software":
                for subkey in key.subkeys():
                    for value in subkey.values():
                            if value.value_type() == 1 or value.value_type() == 2 or (value.value_type() == 4 and "_" not in value.name() and int(value.value()) > 1) or value.value_type() == 11 or value.value == "":
                                    csv_data = [value.name(), value.value(), bookmark_json["LongDescription"], bookmark_json["Category"], bookmark_json["KeyPath"], bookmark_json["HiveType"], reg_hive]
                                    csv_write.writerow(csv_data)
            for value in key.values():
                if value.value_type() == 1 or value.value_type() == 2 or (value.value_type() == 4 and "_" not in value.name() and int(value.value()) > 1) or value.value_type() == 11 or value.value == "":
                    csv_data = [value.name(), value.value(), bookmark_json["LongDescription"], bookmark_json["Category"], bookmark_json["KeyPath"], bookmark_json["HiveType"], reg_hive]
                    csv_write.writerow(csv_data)
        except Registry.RegistryKeyNotFoundException:
            continue
if __name__ == '__main__':
    regparser(argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7])
