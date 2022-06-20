import smtplib
from email.mime.text import MIMEText
from resources.redmine import redmine
from resources import apiError
from resources import logger

class Mail:
    def __init__(self):
        self.__get_account_and_password()
        self.__init_mail_server()

    def __get_account_and_password(self):        
        self.smtp_server, self.smtp_server_port, self.smtp_server_account, \
        self.smtp_server_password = get_basic_mail_info()

    @staticmethod
    def check_mail_server(domain=None, port=None, account=None, password=None):
        smtp_server, smtp_server_port, smtp_server_account, \
        smtp_server_password = get_basic_mail_info()
        domain = domain or smtp_server
        port = port or smtp_server_port
        account = account or smtp_server_account
        password = password or smtp_server_password
        server = None

        try:
            server = smtplib.SMTP(domain, port)
        except Exception as e:
            logger.logger.exception(str(e))
            raise apiError.DevOpsError(404, "Connection refused, port or server are incorrect.",
                        error=apiError.login_email_error())

        server.starttls()
        try:
            server.login(account, password)
        except smtplib.SMTPAuthenticationError as err:
            logger.logger.exception(str(err))
            if domain.endswith("gmail.com"):
                raise apiError.DevOpsError(404, 'Account needs to apply apppassord to login.',
                          error=apiError.gmail_need_apply_apppassword(account))
            raise apiError.DevOpsError(404, 'SMTP auth error',
                          error=apiError.login_email_error())
        except Exception as e:
            logger.logger.exception(str(e))
            raise apiError.DevOpsError(404, 'Account or password are incorrect',
                          error=apiError.login_email_error())

        return server
                            
    def __init_mail_server(self):
        try:
            self.server = self.check_mail_server()
        except:
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


def get_basic_mail_info():
        mail_info = redmine.rm_get_mail_setting().get("smtp_settings", {})
        return mail_info.get("domain"), \
                mail_info.get("port"), \
                mail_info.get("user_name"), \
                mail_info.get("password")


def mail_server_is_open():
    '''
    Based on redmine server settings(default it's open), 
    if address and port are being set, then is true.
    '''
    mail_info = redmine.rm_get_mail_setting().get("smtp_settings")
    if mail_info is None:
        return False
    return mail_info.get("address") is not None and mail_info.get("port") is not None
