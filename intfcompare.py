from ciscoconfparse import CiscoConfParse
import getpass
import ezsshclient
import yaml
import argparse
import pwencrypt

def findlistdiffs(l1, l2):
    s = set([x.strip() for x in l1]).symmetric_difference([x.strip() for x in l2])
    return s

def DecryptPW(password):
    aes = pwencrypt.AESCipher(encryption_key)
    return aes.decrypt(password)


if __name__ == '__main__':
    device_list = []
    cmd_list = []
    result_dict = {}
    userid_list = []
    password_list = []
    device_dict = {}
    parser = argparse.ArgumentParser(description='''intfcompare.py -- Version 1.0 --
        This script will compare interface configuration between two Cisco devices
        and output the differences.''')
    parser.add_argument('-source', help='A YAML file containing the device information',
                        required=False)
    args = parser.parse_args()

    if args.source:
        try:
            with open(args.source, "r") as f:
                yamlfile = f.read()
            device_dict = yaml.load(yamlfile)
            print ("Enter decryption key:")
            encryption_key = getpass.getpass()
        except:
            print("ERROR: Unable to open {0}".format(args.source))
            quit()

    if device_dict:
        for key in device_dict:
            device_list.append(device_dict[key]['ip'])
            cmd_list.append(device_dict[key]['command'])
            userid_list.append(device_dict[key]['username'])
            password_list.append(DecryptPW(device_dict[key]['password']))
            if 'stack_number' in device_dict[key]:
                stack_number = device_dict[key]['stack_number']
    else:
        device_list.append(raw_input("Enter IP/Hostname: "))
        cmd_list.append(raw_input("Enter the command to run on the 1st device: "))
        stack_number = raw_input("Switch stack number: ")
        userid_list.append(raw_input("Username: "))
        password_list.append(getpass.getpass())
        device_list.append(raw_input("Enter IP/Hostname: "))
        cmd_list.append(raw_input("Enter the command to run on the 2nd device: "))
        userid_list.append(raw_input("Username: "))
        password_list.append(getpass.getpass())


    for i, switch in enumerate(device_list):
        command = cmd_list[i]
        userid = userid_list[i]
        password = password_list[i]
        target = ezsshclient.ezssh()
        try:
            target.connect(switch, userid, password)
            connect_success = True
        except Exception as e:
            print ('Error connecting to {}: {}'.format(switch, e))

        if target.isconnected():
            print ('Successfully connected to {}!'.format(switch))
            print ('Running commands...')

            '''Run each command on the device and return the output'''
            output_list = []
            output = target(command)
            output_list.append(output)
            result_dict[switch] = output_list

            target.disconnect()

    for key in result_dict.keys():
        outputfile = open('{0}.cfg'.format(key),'w')
        for line in result_dict[key]:
            outputfile.write(line + '\n')
        outputfile.close()


    parsed_switch_config = CiscoConfParse('{0}.cfg'.format(device_list[0]))
    parsed_fex_config = CiscoConfParse('{0}.cfg'.format(device_list[1]))


    switch_config_list = parsed_switch_config.find_children('^interface GigabitEthernet{0}/0/[0-9][0-9]*'.format(stack_number))
    fex_config_list = parsed_fex_config.find_children('^interface')

    sw_intf_dict = {}
    fex_intf_dict = {}

    for line in switch_config_list:
        if 'interface' in line:
            i,intf = line.split()
            intf = intf[intf.rfind('/'):].strip('/')
            sw_intf_dict[intf] = []
        else:
            sw_intf_dict[intf].append(line)

    for line in fex_config_list:
        if 'interface' in line:
            i, intf = line.split()
            intf = intf[intf.rfind('/'):].strip('/')
            fex_intf_dict[intf] = []
        else:
            fex_intf_dict[intf].append(line)


    for i in range(1,49):
        l = findlistdiffs(sw_intf_dict[str(i)],fex_intf_dict[str(i)])
        output_list = []
        diff_found = False
        print('Interface {0}:'.format(i))
        for line in l:
            if not 'spanning-tree portfast' in line\
                    and not 'switchport mode access' in line\
                    and not 'switchport trunk encapsulation' in line:
                output_list.append('\x1b[1;31;40m' + line + '\x1b[0m')
                diff_found = True
            else:
                diff_found = False
        if diff_found:
            print ('  Switch 1:')
            for cfgline in sw_intf_dict[str(i)]:
                print '    {0}'.format(cfgline)
            print ('  Switch 2:')
            for cfgline in fex_intf_dict[str(i)]:
                print '    {0}'.format(cfgline)
            print ('  Diffs:')
            for line in output_list:
                print ('    ' + line)










