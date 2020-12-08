
class AccountManager:
    """This class manages accounts that are registered"""

    def __init__(self, filename):
        """Default constructor, specifies accounts file"""
        self.filename = filename
        return

    def addUser(self, username, password):
        """Adds a new user to the accounts file, returns True if successful"""
        inF = open(self.filename, "r")
        oldContent = inF.read()
        if username.decode() in oldContent:
            return False
        inF.close()

        outF = open(self.filename, "w")
        outF.write(username.decode() + " " + password.decode() + "\n" + oldContent)
        outF.close()
        return True

    def verifyUser(self, username, password):
        """Verifies user"""
        inF = open(self.filename, "r")
        user, pwd = username.decode(), password.decode()
        for line in inF:
            factors = line.split()
            if len(factors) != 2:
                continue
            if factors[0] == user and factors[1] == pwd:
                return True
        inF.close()
        return False


