import re

# This class does not work with numeric attributes, only with String
# Use the method redact and put your patterns as the example:
# SENSITIVE_PATTERNS = [
#     r"\d{3}-\d{2}-\d{4}",  # Social Security Number (SSN) pattern
#     r"\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}",  # Credit card number pattern
#     r"\(?\d{3}\)?[-\s.]?\d{3}[-\s.]?\d{4}",  # Phone number
#     r"(0[1-9]|1[0-2])[-/.](0[1-9]|[12][0-9]|3[01])[-/.](19|20)\d\d",  # date of birth
#     r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",  # IP address
#     r"[a-zA-Z0-9]{32}"  # API key
# ]
#
# ATTRIBUTE_PATTERNS = [
#     "nome",
#     "cpf",
#     "teste",
#     "valor",
#     "original",
#     "type",
#     "solicitacaoPagador",
#     "chave",
#     "description",
#     "items",
#     "example"
# ]

class Redaction():

    def repl_value2(self, message, pattern):
        flag_aspas = False
        flag_attribute = False
        # flag_vezes = 0
        flag_dois_pontos = False
        flag_colchetes = False
        i = 0
        z = pattern
        str_acc = ""
        while (i < len(message)):
            try:
                if (message[i:i + len(z)] == z and (message[i + len(z):i + len(z) + 1] == "'" or message[i + len(z):i + len(z) + 1] == "\"")):
                    flag_attribute = True
                    flag_aspas = True
            except:
                print("except")
            if (message[i] == ":" and not flag_aspas and flag_attribute):
                flag_dois_pontos = True
            if (flag_aspas and message[i] != "'" and message[i] != "\"" and flag_attribute and flag_dois_pontos):
                str_acc = str_acc + message[i]
                message = message[0:i] + "*" + message[i + 1:len(message) + i]
            if (message[i] == "{" and flag_dois_pontos and not flag_aspas):
                flag_attribute = False
                flag_dois_pontos = False
                flag_aspas = False
                flag_colchetes = False
            if ((message[i] == "}" or message[i] == "]") and not flag_aspas):
                flag_attribute = False
                flag_dois_pontos = False
                flag_aspas = False
                flag_colchetes = False
                str_acc = ""
            if (flag_dois_pontos and not flag_aspas and message[i] == "["):
                flag_colchetes = True
            if (message[i] == "," and not flag_aspas and not flag_colchetes):
                flag_attribute = False
                flag_dois_pontos = False
                flag_aspas = False
                flag_colchetes = False
                str_acc = ""
            if ((message[i] == "'" or message[i] == "\"")):
                flag_aspas = not flag_aspas
            if (flag_aspas == False and flag_attribute == True and flag_dois_pontos and len(str_acc) > 0 and not flag_colchetes):
                flag_attribute = False
                flag_dois_pontos = False
                str_acc = ""
            i = i + 1
        return message

    def repl_value(self, message, pattern):
        flag_aspas = False
        flag_attribute = False
        # flag_vezes = 0
        flag_dois_pontos = False
        flag_colchetes = False
        flag_string = True
        flag_descobre_tipo = False
        i = 0
        z = pattern
        str_acc = ""
        while (i < len(message)):
            try:
                if (message[i:i + len(z)] == z and (message[i + len(z):i + len(z) + 1] == "'" or message[i + len(z):i + len(z) + 1] == "\"")):
                    flag_attribute = True
                    flag_aspas = True
            except:
                print("except")
            if (message[i] == ":" and not flag_aspas and flag_attribute):
                flag_dois_pontos = True
                flag_descobre_tipo = True
            if ((flag_aspas and message[i] != "'" and message[i] != "\"" and flag_attribute and flag_dois_pontos)
                    or (message[i] in "0123456789." and flag_attribute and flag_dois_pontos and not flag_string)):
                str_acc = str_acc + message[i]
                message = message[0:i] + "*" + message[i + 1:len(message) + i]
            if (message[i] == "{" and flag_dois_pontos and not flag_aspas):
                flag_attribute = False
                flag_dois_pontos = False
                flag_aspas = False
                flag_colchetes = False
                flag_descobre_tipo = False
                flag_string = True
            if ((message[i] == "}" or message[i] == "]") and not flag_aspas):
                flag_attribute = False
                flag_dois_pontos = False
                flag_aspas = False
                flag_colchetes = False
                flag_descobre_tipo = False
                flag_string = True
                str_acc = ""
            if ((message[i] == "}" or message[i] == "]") and not flag_aspas and not flag_string):
                flag_attribute = False
                flag_dois_pontos = False
                flag_aspas = False
                flag_colchetes = False
                flag_descobre_tipo = False
                flag_string = True
                str_acc = ""
            if (flag_dois_pontos and not flag_aspas and message[i] == "["):
                flag_colchetes = True
            if (message[i] == "," and not flag_aspas and not flag_colchetes and not flag_string):
                flag_attribute = False
                flag_dois_pontos = False
                flag_aspas = False
                flag_colchetes = False
                flag_descobre_tipo = False
                flag_string = True
                str_acc = ""
            if ((message[i] == "'" or message[i] == "\"")):
                flag_aspas = not flag_aspas
                if (flag_descobre_tipo):
                    flag_string = True
                    flag_descobre_tipo = False
            if (message[i] in "01234567890." and flag_descobre_tipo):
                flag_string = False
                flag_descobre_tipo = False
                str_acc = str_acc + message[i]
                message = message[0:i] + "*" + message[i + 1:len(message) + i]
            if (flag_aspas == False and flag_attribute == True and flag_dois_pontos and len(str_acc) > 0 and not flag_colchetes and flag_string):
                flag_attribute = False
                flag_dois_pontos = False
                flag_descobre_tipo = False
                str_acc = ""
            i = i + 1
        return message

    def repl(self, attribute_pattern, message):
        msg_return = []
        for pattern in attribute_pattern:
            message = self.repl_value(message, pattern)
        return message

    def change(self, sensitive_pattern, message):
        for pattern in sensitive_pattern:
            message = re.sub(pattern, "<REDACTED>", message)
        return message

    def redact(self, sensitive_pattern, attribute_pattern, message):
        message = self.repl(attribute_pattern, message)
        message = self.change(sensitive_pattern, message)
        return message
