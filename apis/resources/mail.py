import smtplib
from email.mime.text import MIMEText
from resources.redmine import redmine
import config

class Mail:
    def __init__(self):
        self.smtp_server = 'smtp.gmail.com'
        self.smtp_server_port = 587
        self.__get_account_and_password()
        self.__init_mail_server(self.smtp_server_account, self.smtp_server_password)

    def __get_account_and_password(self):
        mail_info = redmine.rm_get_mail_setting().get("smtp_settings", {})
        self.smtp_server_account = mail_info.get("user_name")
        self.smtp_server_password = mail_info.get("password")


    def __init_mail_server(self, account, password):
        try:
            self.server = smtplib.SMTP(self.smtp_server, self.smtp_server_port)
            self.server.starttls()
            self.server.login(account, password)
        except smtplib.SMTPAuthenticationError as err:
            self.server = None


    def send_email(self, receiver, title, message):
        text = MIMEText(message, 'plain', 'utf-8')
        text['Subject'] = title
        text['From'] = self.smtp_server_account
        text['To'] = receiver
        text['Disposition-Notification-To'] = self.smtp_server_account

        if self.server is not None:
            self.server.sendmail(self.smtp_server_account, receiver, text.as_string())
            self.server.quit()
