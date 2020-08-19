import pymongo
import pprint
import collections
from bson.son import SON
import json
from cryptography.fernet import Fernet

def createkey():
    key = Fernet.generate_key()
    file = open('key.key', 'wb')
    file.write(key)
    file.close()
    print("Encrypt key file created.")
    return key

def openkey():
    try:
        file = open('key.key', 'rb')
        key = file.read()
        return key
    except (ValueError, FileNotFoundError) as e:
        print('Key file not found, generating')
        createkey()

def load_json(file_name):
    with open(file_name) as data_file:
        data = json.load(data_file)
    return data

def encrypt_users(users, cipher_suite):
    for user in users:
        pwd_enc = user.get('pwd_enc')
        pwd = user.get('pwd')
        if not pwd_enc:
            pwd_bytes = pwd.encode('utf-8')
            pwd_enc = cipher_suite.encrypt(pwd_bytes).decode('utf-8')
            user['pwd_enc'] = pwd_enc
            del user['pwd']
    return users

def decrypt_users(users, cipher_suite):
    for user in users:
        pwd_enc = user.get('pwd_enc')
        pwd = user.get('pwd')
        if not pwd:
            pwd_enc_bytes = pwd_enc.encode('utf-8')
            pwd = cipher_suite.decrypt(pwd_enc_bytes).decode('utf-8')
            user['pwd'] = pwd
            del user['pwd_enc']
    return users

def write_users(users, file_name):
    with open(file_name, 'w') as outfile:
        json.dump(users, outfile, indent=4)

def update_mongo_roles(roles, admin_db, drop_others=True):
    roles_set = set()
    for role in roles:
        roleCommand = collections.OrderedDict()
        roleName = role["role"]
        roles_set.add(roleName)
        rolesInfo = admin_db.command({'rolesInfo': roleName})
        existingRole = rolesInfo.get('roles', [])
        if (existingRole):
            print("existing role: " + roleName)
            roleCommand['updateRole'] = roleName
            roleCommand.move_to_end('updateRole', False)
            roleCommand.update(role)
            del roleCommand['role']
            admin_db.command(roleCommand)
        else:
            print("new role: " + roleName)
            roleCommand['createRole'] = roleName
            roleCommand.move_to_end('createRole', False)
            roleCommand.update(role)
            del roleCommand['role']
            admin_db.command(roleCommand)
    
    if drop_others:
        rolesInfo = admin_db.command({'rolesInfo': 1})
        allRoles = rolesInfo['roles']
        for role in allRoles:
            roleName = role["role"]
            customData = role.get('customData', {'doNotDrop': False})
            if not roleName in roles_set and not customData.get('doNotDrop'):
                print("dropping role " + roleName)
                dropRoleCommand = collections.OrderedDict()
                dropRoleCommand["dropRole"] = roleName
                admin_db.command(dropRoleCommand)
                roles_set.remove(roleName)
    return roles_set

def update_mongo_users(users, roles_set, admin_db, drop_others=True):
    usersSet = set()
    for user in users:
        userCommand = collections.OrderedDict()
        userName = user["user"]
        missingRoles = set(user["roles"]).difference(roles_set)
        if missingRoles:
            print("missingRoles: " + str(missingRoles) + ", skipping user " + userName)
            continue
        
        usersSet.add(userName)
        usersInfo = admin_db.command({'usersInfo': userName})
        existingUser = usersInfo.get('users', [])
        if (existingUser):
            print("existing user: " + userName)
            userCommand['updateUser'] = userName
            userCommand.move_to_end('updateUser', False)
            userCommand.update(user)
            del userCommand['user']
            admin_db.command(userCommand)
        else:
            print("new user: " + userName)
            userCommand['createUser'] = userName
            userCommand.move_to_end('createUser', False)
            userCommand.update(user)
            del userCommand['user']
            admin_db.command(userCommand)

    if drop_others:
        usersInfo = admin_db.command({'usersInfo': 1})
        allUsers = usersInfo['users']
        for user in allUsers:
            userName = user["user"]
            customData = user.get('customData', {'doNotDrop': False})
            if not userName in usersSet and not customData.get('doNotDrop'):
                print("dropping user " + userName)
                dropUserCommand = collections.OrderedDict()
                dropUserCommand["dropUser"] = userName
                admin_db.command(dropUserCommand)

if __name__=="__main__":

    client = pymongo.MongoClient("localhost:27017")
    admin_db = client["admin"]
    key = openkey()
    cipher_suite = Fernet(key)

    roles = load_json("roles.json")
    roles_set = update_mongo_roles(roles, admin_db)

    users = load_json("users.json")
    users = encrypt_users(users, cipher_suite)
    write_users(users, "users.json")
    users = decrypt_users(users, cipher_suite)
    update_mongo_users(users, roles_set, admin_db)