# MediLabAPI
We will be designing a Laboratory Management System using Flask and ReactJS

## Step1 : Helper Functions
This are functions we will use to assist us in API operations e,g sms, mpesa, email,...
Use the code below:
```
# sending an sms
import africastalking
africastalking.initialize(
    username="joe2022",
    api_key="aab3047eb9ccfb3973f928d4ebdead9e60beb936b4d2838f7725c9cc165f0c8a"
    #justpaste.it/1nua8
)
sms = africastalking.SMS
def send_sms(phone, message):
    recipients = [phone]
    sender = "AFRICASTKNG"
    try:
        response = sms.send(message, recipients)
        print(response)
    except Exception as error:
        print("Error is ", error)


#send_sms("+254729225710", "This is test message on Fleet.")
import requests
import base64
import datetime
from requests.auth import HTTPBasicAuth


def mpesa_payment(amount, phone, invoice_no):
        # GENERATING THE ACCESS TOKEN
        consumer_key = "GTWADFxIpUfDoNikNGqq1C3023evM6UH"
        consumer_secret = "amFbAoUByPV2rM5A"

        api_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"  # AUTH URL
        r = requests.get(api_URL, auth=HTTPBasicAuth(consumer_key, consumer_secret))

        data = r.json()
        access_token = "Bearer" + ' ' + data['access_token']

        #  GETTING THE PASSWORD
        timestamp = datetime.datetime.today().strftime('%Y%m%d%H%M%S')
        passkey = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'
        business_short_code = "174379"
        data = business_short_code + passkey + timestamp
        encoded = base64.b64encode(data.encode())
        password = encoded.decode('utf-8')

        # BODY OR PAYLOAD
        payload = {
            "BusinessShortCode": "174379",
            "Password": "{}".format(password),
            "Timestamp": "{}".format(timestamp),
            "TransactionType": "CustomerPayBillOnline",
            "Amount": amount,  # use 1 when testing
            "PartyA": phone,  # change to your number
            "PartyB": "174379",
            "PhoneNumber": phone,
            "CallBackURL": "https://modcom.co.ke/job/confirmation.php",
            "AccountReference": "account",
            "TransactionDesc": "account"
        }

        # POPULAING THE HTTP HEADER
        headers = {
            "Authorization": access_token,
            "Content-Type": "application/json"
        }

        url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"  # C2B URL

        response = requests.post(url, json=payload, headers=headers)
        print(response.text)

# mpesa_payment("2", "254729225710")
import bcrypt
def hash_password(password):
    bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)
    print("Bytes ", bytes)
    print("Salt ", salt)
    print("Hashed password ", hash.decode())
    return hash.decode()

#hash_password("kenya1234")
# $2b$12$LyTDdwhw5GHR6ILxTSrCfu69/x4xpihitQ3QZXUHOXa7YRQtg2FcO
def hash_verify(password,  hashed_password):
    bytes = password.encode('utf-8')
    result = bcrypt.checkpw(bytes, hashed_password.encode())
    print(result)
    return result


#hash_verify("kenya1234", "$2b$12$LyTDdwhw5GHR6ILxTSrCfu69/x4xpihitQ3QZXUHOXa7YRQtg2FcO")
from cryptography.fernet import  Fernet
def gen_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)


#gen_key()
#gAAAAABkgERvXDGZguFb_LfkU760glQJuR3JUNYN8qN_dOdd8aIYKOkKxvAOK5_0_mPc9FOQb8e_2EvyhBmWW5q_kjQbMYXWDA==
#gAAAAABkgERvXDGZguFb_LfkU760glQJuR3JUNYN8qN_dOdd8aIYKOkKxvAOK5_0_mPc9FOQb8e_2EvyhBmWW5q_kjQbMYXWDA==

def load_key():
    return open("key.key", "rb").read()

#print(load_key())

def encrypt(data):
    key = load_key()
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    print("Plain ", data)
    print("Encrypted ", encrypted_data.decode())

encrypt("+254729225710")

#gAAAAABkgEQtc0-hFW6XGBPp9OBSE0wzbltYUt7KBHa5D9fksynwnlEMHDD-GMkQ8NckXxwxlBXFjuK0H-kaGQjuWYb0yxNN4A==
#gAAAAABkgEROMW7LpQrmR3AwzbdPMcUsjG_LHYYbC5ZSP_0r7IQn3UePWGxB9ykPvNSe-cVwr2bHf0_ha_KGvoc3ar0zuFZB1A==


def decrypt(encrypted_data):
    key = load_key()
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    print("Decrypted data ", decrypted_data.decode())
    return decrypted_data.decode()

#decrypt("gAAAAABjIY3vZqXEHBV9DIvizYUfsA6uPxx1pT16_OyopLYIAg4x52wUMwVWhRS2_IgVcQfKKZbWPRWmrcfJ15Nu3zj7rMdwWw==")
def gen_random():
    import string
    import random
    # initializing size of string
    N = 6
    # using random.choices()
    # generating random strings
    res = ''.join(random.choices(string.digits, k=N))
    # print result
    print("The generated random string : " + str(res))
    return str(res)

#gen_random()
def send_email():
    import smtplib
    # creates SMTP session
    s = smtplib.SMTP('smtp.gmail.com', 587)
    # start TLS for security
    s.starttls()
    # Authentication
    s.login("modcomlearning@gmail.com", "")
    # message to be sent
    message = "This is a test email"
    # sending the mail
    s.sendmail("modcomlearning@gmail.com", "mwangiplus@gmail.com", message)
    # terminating the session
    s.quit()

#send_email()

def gen_pdf():
    # Python program to create
    # a pdf file
    from fpdf import FPDF
    # save FPDF() class into a
    # variable pdf
    pdf = FPDF()
    # Add a page
    pdf.add_page()
    # set style and size of font
    # that you want in the pdf
    pdf.set_font("Arial", size=15)
    # create a cell
    pdf.cell(200, 10, txt="ModcomInstitute of tech",
             ln=1, align='L')
    # add views cell
    pdf.cell(200, 10, txt="A Computer Science portal for geeks.",
             ln=2, align='C')
    pdf.cell(200, 10, txt="A Computer Science portal for geeks.",
             ln=3, align='C')
    # save the pdf with name .pdf
    pdf.output("cv.pdf")

#gen_pdf()


import re
def passwordValidity(password):
    # define a function to check password strength
    if (len(password) < 8):
        return "inValid Password less than 8"

    elif not re.search("[a-z]", password):
        return "inValid Password no small letter"

    elif not re.search("[A-Z]", password):
        return "inValid Password no caps"

    elif not re.search("[0-9]", password):
        return "inValid Password no numbers"

    elif not re.search("[_@$]", password):
        return "inValid Password no symbol"
    else:
        return True

#print(passwordValidity("jNjkbj334kffdghfdh"))
import re
def check_phone(phone):
    regex = "^\+254\d{9}"
    if not re.match(regex, phone)  or len(phone) !=13:
        print("Phone Not Ok")
        return False
    else:
        print("Phone Ok")
        return True

#check_phone("+254729225710")

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(sender_email, sender_password, recipient_email, subject, body):
    # Set up the SMTP server details
    smtp_server = 'smtp.example.com'  # Replace with your SMTP server address
    smtp_port = 587  # Replace with your SMTP server port (587 is a common TLS port)

    # Create the email message
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = recipient_email
    message['Subject'] = subject

    # Attach the body of the email
    message.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the SMTP server and initiate TLS encryption
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()

        # Log in to the SMTP server using your credentials
        server.login(sender_email, sender_password)

        # Send the email
        server.sendmail(sender_email, recipient_email, message.as_string())

        print("Email sent successfully!")
    except Exception as e:
        print("Error sending email:", str(e))
    finally:
        # Close the connection to the SMTP server
        server.quit()

# Example usage
sender_email = 'your_email@example.com'
sender_password = 'your_email_password'
recipient_email = 'recipient@example.com'
subject = 'Test Email'
body = 'This is a test email sent using Python!'

# send_mail(sender_email, sender_password, recipient_email, subject, body)

```
## Install the Required Libraries for the helper functions
```
pip3 install africastalking
```

```
pip3 install bcrypt
```

```
pip3 install cryptography
```

```
pip3 install requests
```

## Add LabTests

```
class LabTests(Resource):
    def post(self):
        data = request.json
        lab_id = data['lab_id']

        connection = pymysql.connect(host='localhost', user='root', password='', database='medilab5')

        sql = "select * from lab_tests where lab_id = %s"
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql, lab_id)

        count = cursor.rowcount
        if count == 0:
            return jsonify({'message': 'No lab Found'})
        else:
            lab_tests = cursor.fetchall()
            return jsonify(lab_tests)
```


